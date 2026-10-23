"""
tests/test_family_coverage.py

Comprehensive test suite verifying detection coverage across 11 weak scam families
and 6 difficult benign categories.

- Dev set (DEV_SCAM_SAMPLES + DEV_BENIGN_SAMPLES):
    - 11 scam families x 6 samples = 66 scam cases (must achieve 100% pass, score >= 75)
    - 6 benign categories x 6 samples = 36 benign cases (must achieve 100% pass, score < 40)
- Check set (CHECK_SCAM_SAMPLES + CHECK_BENIGN_SAMPLES):
    - Completely separate evaluation set written in original words
    - Must achieve >= 60% pass rate
"""

import pytest
from codebase.agents.explainable_agent import ExplainableAgent


# =============================================================================
# DEV DATASET: 11 SCAM FAMILIES (>= 6 SAMPLES EACH)
# =============================================================================
DEV_SCAM_SAMPLES = [
    # 1. Đầu tư / tiền ảo nhóm kín
    ("invest_01", "Tham gia nhóm VIP Telegram chuyên gia đọc lệnh kéo 1-1 sàn Forex bao lỗ lợi nhuận 30%/ngày nạp vốn 2 triệu.", 75),
    ("invest_02", "Đầu tư tiền ảo USDT trên sàn quốc tế cam kết sinh lời 25% mỗi ngày, vào vốn 5 triệu rút lãi trong ngày.", 75),
    ("invest_03", "Sàn đầu tư tài chính 4.0 cam kết lãi khủng không rủi ro, nạp tiền vào quỹ đảm bảo 3 triệu nhận ngay hoa hồng.", 75),
    ("invest_04", "Nhóm Zalo cao thủ bắn lệnh bao win 100%, bảo toàn vốn, chuyển khoản 5 triệu mở tài khoản VIP.", 75),
    ("invest_05", "Kèo đầu tư chứng khoán quốc tế sinh lời 20% mỗi tuần, chắc chắn có lãi, nạp vốn thử 1 triệu đi bạn.", 75),
    ("invest_06", "Vào room VIP chuyên gia kéo về bờ sàn tiền ảo, cam kết hoàn vốn 100%, nạp trước 4 triệu để kích hoạt tài khoản.", 75),

    # 2. Mượn tiền / nick bạn bị hack
    ("borrow_01", "Mày ơi tao bị lỗi app Techcombank không chuyển được tiền, mày bắn gấp cho tao 2 triệu vào stk này tí tao bắn lại.", 75),
    ("borrow_02", "Anh ơi em bị kẹt tiền đóng tiền phòng trọ gấp, cho em mượn 3 triệu chiều nhận lương em gửi lại liền.", 75),
    ("borrow_03", "Alo bạn ơi, tài khoản ngân hàng của mình bị hết hạn mức, bạn chuyển giúp mình 1 triệu vào stk 987654 tối mình chuyển trả nhé.", 75),
    ("borrow_04", "Ông ơi tôi bị mất điện thoại dùng số mới này, đang kẹt việc gấp ông bắn cho tôi mượn 4 triệu mai tôi trả.", 75),
    ("borrow_05", "Chị ơi em mượn tạm 2 triệu thanh toán tiền thuốc gấp cho mẹ, lát em nhờ người nhà chuyển khoản trả chị ngay.", 75),
    ("borrow_06", "Mày hả, tao đang đi mua đồ mà tài khoản Vietinbank bị bảo trì, chuyển hộ tao 1 triệu 5 vào stk cửa hàng tí về tao trả.", 75),

    # 3. Tình cảm + chuyển tiền (Romance scam)
    ("romance_01", "Anh là kỹ sư dầu khí ở nước ngoài, anh gửi tặng em kiện hàng quà tặng và tiền tiết kiệm, em chuyển giúp phí hải quan 5 triệu nhé.", 75),
    ("romance_02", "Em quen anh qua Tinder, anh ấy là quân nhân bảo gửi thùng hàng về Việt Nam cho em và nhờ em nộp thuế thông quan để nhận.", 75),
    ("romance_03", "Bạn trai ngoại quốc gửi cho em hộp quà chứa kim cương và ngoại tệ, hải quan sân bay yêu cầu đóng phí lưu kho 10 triệu để nhận quà.", 75),
    ("romance_04", "Anh bạn quen qua mạng ở Mỹ bảo gửi vali quà cưới về cho hai đứa, nhờ em chuyển khoản nộp phí vận chuyển quốc tế vào stk cá nhân.", 75),
    ("romance_05", "Người yêu online bảo gửi thùng hàng quà tặng từ London về, bên chuyển phát gọi yêu cầu em đóng thuế hải quan 3 triệu để thông quan.", 75),
    ("romance_06", "Quen qua Facebook, anh ấy bảo là bác sĩ quân y gửi kiện hàng quà tặng về Việt Nam, nhờ em chuyển 6 triệu tiền lệ phí sân bay.", 75),

    # 4. Giả OTP / khóa tài khoản ngân hàng
    ("bank_otp_01", "Vietcombank kính báo: Tài khoản của quý khách bị tạm khóa do nghi vấn gian lận, truy cập https://vcb-security.top xác thực ngay.", 75),
    ("bank_otp_02", "Techcombank: Thẻ tín dụng của bạn bị ngừng giao dịch, vui lòng đăng nhập vào http://techcombank-online.xyz để mở khóa trong 2h.", 75),
    ("bank_otp_03", "Ngân hàng MB: Phát hiện đăng nhập bất thường, cung cấp mã OTP cho chuyên viên ngân hàng ngay để tránh bị phong tỏa tài khoản.", 75),
    ("bank_otp_04", "BIDV thông báo tài khoản bị khóa do chưa định danh sinh trắc học, truy cập http://bidv-ebank.xyz xác thực trước 24h.", 75),
    ("bank_otp_05", "Tổng đài viên ngân hàng gọi thông báo tài khoản bị tấn công, yêu cầu đọc mã OTP và số thẻ cho nhân viên để hủy lệnh chuyển tiền.", 75),
    ("bank_otp_06", "ACB cảnh báo: Tài khoản của bạn sẽ bị khóa vĩnh viễn trong 2 giờ, vào link https://acb-digit.top cập nhật thông tin ngay.", 75),

    # 5. Bill giả / hoàn tiền
    ("fake_bill_01", "Khách hàng gửi ảnh chụp bill chuyển khoản Vietinbank thành công 5 triệu nhưng kiểm tra tài khoản chưa thấy nổi tiền, giục gửi hàng ngay.", 75),
    ("fake_bill_02", "Bên mua gửi hóa đơn VietQR báo thanh toán thành công 3 triệu, bảo mạng lag tiền chưa vào tài khoản và yêu cầu giao hàng trước.", 75),
    ("fake_bill_03", "Người lạ chuyển nhầm 10 triệu vào tài khoản của bạn, sau đó gửi link yêu cầu bạn đăng nhập để làm thủ tục hoàn trả tiền.", 75),
    ("fake_bill_04", "Khách gửi bill chuyển khoản thành công nhưng số dư chưa tăng, dọa báo công an nếu em không giao hàng đi ngay.", 75),
    ("fake_bill_05", "Ảnh biên lai ngân hàng báo chuyển khoản thành công 4 triệu nhưng app banking chưa có biến động số dư, khách giục bấm giao hàng.", 75),
    ("fake_bill_06", "Đối tượng gửi ảnh bill chuyển tiền giả bảo đã trả nợ rồi và bảo app bị lỗi nên chưa ting ting, ép giao giấy tờ nhà.", 75),

    # 6. Cho vay online / phí giải ngân
    ("loan_01", "Hồ sơ vay online 50 triệu đã được duyệt, quý khách vui lòng nộp phí thẩm định hồ sơ 2 triệu vào stk công ty để giải ngân.", 75),
    ("loan_02", "Hạn mức gói vay 100 triệu của bạn bị đóng băng do sai số tài khoản, cần chuyển khoản đóng tiền đối ứng 5 triệu để mở khóa khoản vay.", 75),
    ("loan_03", "Vay vốn tiêu dùng nhanh lãi suất thấp, yêu cầu đóng phí bảo hiểm khoản vay 3 triệu trước khi nhận tiền giải ngân.", 75),
    ("loan_04", "Khoản vay online đã duyệt thành công, chuyển khoản nộp phí giải ngân 1 triệu 500k để nhân viên chuyển tiền về tài khoản.", 75),
    ("loan_05", "Hồ sơ vay tiền nóng duyệt trong ngày, yêu cầu đóng phí chứng minh thu nhập 2 triệu để hệ thống mở lệnh giải ngân.", 75),
    ("loan_06", "Thông báo phê duyệt khoản vay cá nhân 70 triệu, bạn cần nộp tiền cọc hợp đồng vay 3 triệu để hoàn tất thủ tục nhận tiền.", 75),

    # 7. Giả shipper / hải quan
    ("shipper_01", "Em là shipper giao hàng Tiết Kiệm, đơn hàng của anh bị thiếu cước 80k, anh chuyển khoản gấp vào stk cá nhân của em nhé.", 75),
    ("shipper_02", "Bưu điện thông báo kiện hàng quốc tế của bạn bị hải quan tạm giữ, yêu cầu chuyển khoản nộp phí thông quan 3 triệu vào stk 654321.", 75),
    ("shipper_03", "Shipper gọi báo có bưu phẩm gửi bảo vệ chung cư nhưng chưa thanh toán phí giao, yêu cầu ck gấp 150k vào tài khoản riêng.", 75),
    ("shipper_04", "Cơ quan hải quan sân bay thông báo gói hàng của bạn bị giữ do thiếu thuế thông quan, nộp phạt 5 triệu vào tài khoản cá nhân để nhận hàng.", 75),
    ("shipper_05", "Nhân viên giao hàng Viettel Post gọi báo kiện hàng bị phạt lưu kho, yêu cầu chuyển 200k nộp phí vào stk cá nhân để giao lại.", 75),
    ("shipper_06", "Bên giao hàng Shopee Express thông báo đơn hàng giao không thành công do thiếu tiền cước, yêu cầu ck 100k vào stk shipper.", 75),

    # 8. Việc nhẹ lương cao / tuyển CTV
    ("ctv_01", "Tuyển cộng tác viên chốt đơn Shopee tại nhà kiếm 500k/ngày không cần vốn, yêu cầu đặt cọc phí kích hoạt đại lý 300k.", 75),
    ("ctv_02", "Công việc online xem video Tiktok kiếm tiền, hoa hồng 30%, làm nhiệm vụ nạp tiền 500k để mở khóa tài khoản VIP.", 75),
    ("ctv_03", "Tuyển người làm việc tại nhà đánh giá sản phẩm đơn hàng ảo nhận hoa hồng cao, yêu cầu chuyển khoản nộp tiền cọc 400k.", 75),
    ("ctv_04", "Việc nhẹ lương cao tuyển ctv lướt video kiếm 800k/ngày, làm nhiệm vụ nạp tiền vào quỹ 1 triệu nhận lại cả gốc lẫn lãi.", 75),
    ("ctv_05", "Tuyển cộng tác viên giật đơn Lazada nhận lương theo ngày, yêu cầu thanh toán đơn hàng trước 600k để nhận hoa hồng 20%.", 75),
    ("ctv_06", "Cần tuyển ctv like bài viết facebook kiếm tiền, nộp phí giữ chỗ và nạp tiền làm nhiệm vụ 500k trên Telegram.", 75),

    # 9. Deepfake video call
    ("deepfake_01", "Bạn gọi video call thấy mặt nhưng hình ảnh mờ và giật lag vài giây rồi cúp máy, sau đó nhắn tin nhờ chuyển gấp 5 triệu cấp cứu.", 75),
    ("deepfake_02", "Cuộc gọi video thấy hình bạn bè mồm méo khuôn mặt không tự nhiên mạng báo yếu tắt máy ngay, nhắn tin mượn 3 triệu chuyển khoản.", 75),
    ("deepfake_03", "Video call mờ nhòe chập chờn chỉ nói được mấy giây là tắt, nhắn qua Zalo bảo đang bị tai nạn nhờ bắn giúp 4 triệu viện phí.", 75),
    ("deepfake_04", "Gọi video thấy mặt anh trai nhưng tiếng rè giọng lạ vài giây rồi tắt máy, nhắn tin nhờ chuyển tiền gấp đóng học phí cho cháu.", 75),
    ("deepfake_05", "Nghi vấn deepfake video call thấy hình ảnh giật đơ rồi tắt ngúm, sau đó nhắn tin bảo tài khoản lỗi nhờ chuyển khoản hộ 6 triệu.", 75),
    ("deepfake_06", "Bạn thân gọi video nhòe mặt bảo mạng lag rồi cúp, nhắn tin gấp nhờ chuyển 2 triệu vào stk lạ để chuộc xe bị giữ.", 75),

    # 10. Hỗ trợ kỹ thuật / điều khiển từ xa
    ("tech_01", "Nhân viên kỹ thuật thông báo máy tính bị nhiễm virus độc hại, yêu cầu cài Ultraviewer và đọc ID mật khẩu để quét mã độc từ xa.", 75),
    ("tech_02", "Cảnh báo an ninh mạng phát hiện tài khoản bị xâm nhập, tải phần mềm AnyDesk và cấp quyền trợ năng để chuyên viên bảo vệ tài khoản.", 75),
    ("tech_03", "Kỹ thuật viên hỗ trợ gỡ mã độc gián điệp trên điện thoại, yêu cầu cài đặt TeamViewer QuickSupport và cung cấp ID điều khiển từ xa.", 75),
    ("tech_04", "Bộ phận kỹ thuật gọi báo thiết bị có lỗ hổng bảo mật ngân hàng, yêu cầu bật quyền điều khiển từ xa qua RustDesk để xử lý.", 75),
    ("tech_05", "Chuyên viên IT gọi báo máy tính cơ quan nhiễm mã độc tống tiền, yêu cầu mở Ultraview và cho quyền truy cập thiết bị ngay.", 75),
    ("tech_06", "Hỗ trợ kỹ thuật ứng dụng thuế yêu cầu người dùng cài đặt phần mềm điều khiển từ xa để hướng dẫn sửa lỗi kê khai.", 75),

    # 11. Giả CSKH TMĐT
    ("ecom_01", "Tổng đài CSKH Shopee gọi thông báo quý khách đăng ký nhầm gói hội viên 5 triệu/tháng, yêu cầu chuyển khoản hủy gói ngay kẻo bị trừ tiền.", 75),
    ("ecom_02", "Nhân viên chăm sóc khách hàng Lazada báo đơn hàng của bạn bị lỗi thanh toán kép, yêu cầu chuyển tiền vào tài khoản đối ứng để hoàn tiền.", 75),
    ("ecom_03", "CSKH TikTok Shop thông báo tài khoản gian hàng vi phạm chính sách, yêu cầu nộp tiền phạt vi phạm 4 triệu vào stk để tránh đóng shop.", 75),
    ("ecom_04", "Tổng đài viên Tiki gọi báo khách hàng trúng thưởng tri ân gói mua sắm 10 triệu, yêu cầu nộp phí kích hoạt 1 triệu vào tài khoản cá nhân.", 75),
    ("ecom_05", "Bộ phận hỗ trợ người bán Shopee gọi thông báo tài khoản bị khóa do chưa nâng cấp gói dịch vụ, yêu cầu chuyển khoản 3 triệu để mở lại.", 75),
    ("ecom_06", "CSKH Sendo thông báo bạn kích hoạt nhầm dịch vụ VIP tự động gia hạn 3 triệu mỗi tháng, cần làm theo hướng dẫn chuyển tiền để hủy lệnh.", 75),
]


# =============================================================================
# DEV DATASET: 6 DIFFICULT BENIGN CATEGORIES (>= 6 SAMPLES EACH)
# =============================================================================
DEV_BENIGN_SAMPLES = [
    # 1. Báo chí tường thuật
    ("news_01", "Báo điện tử Dân trí: Công an vừa triệt phá đường dây lừa đảo qua mạng chiếm đoạt hàng chục tỷ đồng của người dân.", 40),
    ("news_02", "Theo báo Tuổi Trẻ, cơ quan cảnh sát điều tra đã khởi tố vụ án lừa đảo công nghệ cao và bắt giữ nhóm đối tượng giả danh cán bộ.", 40),
    ("news_03", "Báo VnExpress đưa tin về các thủ đoạn lừa đảo tuyển cộng tác viên làm nhiệm vụ nạp tiền giật đơn hàng trên mạng xã hội.", 40),
    ("news_04", "Phóng sự truyền hình VTV cảnh báo người dân về chiêu trò lừa đảo tình cảm gửi kiện hàng quà tặng từ nước ngoài về.", 40),
    ("news_05", "Báo Thanh Niên phản ánh tình trạng các đối tượng tạo bill chuyển tiền giả mạo để chiếm đoạt hàng hóa của các shop online.", 40),
    ("news_06", "Báo Tiền Phong đưa tin công an huyện vừa phát tờ rơi tuyên truyền các thủ đoạn lừa đảo giả mạo cơ quan điều tra đe dọa người dân.", 40),

    # 2. Công an / ngân hàng cảnh báo
    ("warning_01", "Công an TP khuyến cáo người dân nâng cao cảnh giác, tuyệt đối không cung cấp mã OTP hoặc mật khẩu ngân hàng cho bất kỳ ai.", 40),
    ("warning_02", "Vietcombank khuyến cáo khách hàng: Ngân hàng không bao giờ yêu cầu cung cấp mã OTP hay thông tin bảo mật qua điện thoại.", 40),
    ("warning_03", "Cục An toàn thông tin cảnh báo người dân tuyệt đối không chuyển tiền vào tài khoản cá nhân của người lạ khi chưa xác minh.", 40),
    ("warning_04", "Cảnh sát khu vực phát tờ rơi khuyến cáo bà con cảnh giác với các cuộc gọi mạo danh cơ quan chức năng đe dọa nộp tiền phạt.", 40),
    ("warning_05", "Ngân hàng Techcombank cảnh báo thủ đoạn lừa đảo cài đặt ứng dụng giả mạo ngoài kho ứng dụng chính thức Google Play.", 40),
    ("warning_06", "Bộ Công an khuyến cáo người dân không bấm vào các đường link lạ và không làm theo hướng dẫn chuyển tiền của người tự xưng là cán bộ điều tra.", 40),

    # 3. Người vừa bị lừa hỏi lời khuyên
    ("victim_01", "Em vừa bị lừa mất 15 triệu qua mạng chuyển vào tài khoản kẻ gian, giờ phải làm sao để báo công an ạ?", 40),
    ("victim_02", "Tôi lỡ chuyển tiền cho bên làm nhiệm vụ online bị lừa rồi, cho tôi hỏi thủ tục làm đơn tố cáo ở cơ quan nào?", 40),
    ("victim_03", "Mọi người cho em xin lời khuyên với, em bị lừa mất 5 triệu cọc việc làm online thì có lấy lại được tiền không?", 40),
    ("victim_04", "Bị lừa chuyển khoản vào tài khoản cá nhân của kẻ mạo danh shipper thì có cách nào nhờ ngân hàng phong tỏa tra soát không ạ?", 40),
    ("victim_05", "Em bị lừa mất tiền mua hàng online, giờ em phải làm gì bây giờ để tố giác tài khoản lừa đảo ạ?", 40),
    ("victim_06", "Xin tư vấn giúp tôi thủ tục báo án lên công an khi bị đối tượng giả danh viện kiểm sát đe dọa chiếm đoạt tài sản.", 40),

    # 4. Chat đời thường nhắc tiền
    ("daily_01", "Mày ơi bắn tiền cà phê 40k hôm qua cho tao nhé, cảm ơn bạn nhiều.", 40),
    ("daily_02", "Chị chuyển khoản tiền cơm trưa văn phòng 55k rồi nhé em ơi, kiểm tra giúp chị nha.", 40),
    ("daily_03", "Tối qua ăn lẩu hết 800k chia đều mỗi đứa 200k nhé, rảnh thì chuyển tiền cho tao.", 40),
    ("daily_04", "Em gửi tiền phòng trọ và tiền điện nước tháng này rồi nhé chị chủ nhà, cảm ơn chị.", 40),
    ("daily_05", "Tôi đã thanh toán tiền mua sách 120k cho bạn rồi nhé, tiền về chưa kiểm tra giúp mình.", 40),
    ("daily_06", "Anh ơi em vừa chuyển khoản trả tiền mua quà sinh nhật cho bạn lúc nãy rồi nhé.", 40),

    # 5. OTP / biến động số dư thật
    ("otp_01", "Vietcombank: Mã OTP của quý khách là 345678 để xác thực giao dịch thanh toán đơn hàng. Tuyệt đối không chia sẻ cho bất kỳ ai.", 40),
    ("otp_02", "Techcombank: Ma OTP cua quy khach la 891234. Khong cung cap ma OTP cho bat ky ai ke ca nhan vien ngan hang.", 40),
    ("otp_03", "MB Bank thông báo: Biến động số dư tài khoản 123456789 +3.000.000 VND lúc 15:30. Nội dung: Chuyen tien luong thang 10.", 40),
    ("otp_04", "ACB: Quý khách vừa thực hiện giao dịch thanh toán trực tuyến thành công 250.000 VND tại Shopee. Số dư hiện tại là 4.500.000 VND.", 40),
    ("otp_05", "Vui lòng nhập mã OTP 654321 để hoàn tất đăng nhập ứng dụng VNeID trên thiết bị mới của bạn.", 40),
    ("otp_06", "BIDV: Số dư tài khoản 987654321 thay đổi -500.000 VND lúc 10:15. Nội dung: Thanh toan hoa don tien dien.", 40),

    # 6. Hỏi cách phòng chống
    ("inquiry_01", "Làm thế nào để phòng tránh bị lừa đảo khi nhận được các cuộc gọi mạo danh công an đe dọa nộp phạt?", 40),
    ("inquiry_02", "Cho em hỏi cách nhận biết dấu hiệu lừa đảo tuyển cộng tác viên chốt đơn hàng trên các trang mạng xã hội?", 40),
    ("inquiry_03", "Làm sao để không bị lừa khi người quen nhắn tin mượn tiền gấp qua mạng xã hội Zalo, Facebook?", 40),
    ("inquiry_04", "Hướng dẫn các biện pháp an toàn bảo mật để tránh bị đánh cắp thông tin tài khoản ngân hàng và mã OTP.", 40),
    ("inquiry_05", "Kinh nghiệm phân biệt giữa tin nhắn biến động số dư thật của ngân hàng và tin nhắn SMS giả mạo thương hiệu.", 40),
    ("inquiry_06", "Làm sao biết được một cuộc gọi video call có phải là deepfake giả dạng người thân để mượn tiền hay không?", 40),
]


# =============================================================================
# CHECK DATASET: 11 SCAM FAMILIES (>= 6 SAMPLES EACH)
# =============================================================================
CHECK_SCAM_SAMPLES = [
    # 1. Đầu tư / tiền ảo nhóm kín
    ("chk_invest_01", "Vào nhóm kín Telegram đầu tư tiền ảo lợi nhuận cam kết 20% mỗi ngày, nạp tiền 3 triệu vào quỹ chuyên gia kéo lệnh.", 75),
    ("chk_invest_02", "Kênh Zalo đầu tư sinh lời 35%/ngày bao win không sợ lỗ, chuyển khoản nạp vốn 5 triệu mở tài khoản VIP.", 75),
    ("chk_invest_03", "Tham gia sàn giao dịch tài chính quốc tế cam kết lợi nhuận khủng x2 tài khoản, nạp trước 10 triệu để chuyên gia đọc lệnh.", 75),
    ("chk_invest_04", "Kèo trade bot tiền kỹ thuật số đảm bảo không lỗ vốn ít lời nhiều, nạp tiền vào sàn 2 triệu rút lãi sau 24h.", 75),
    ("chk_invest_05", "Sàn Forex ủy thác đầu tư sinh lời 15%/ngày cam kết hoàn vốn, chuyển 3 triệu vào tài khoản đảm bảo.", 75),
    ("chk_invest_06", "Nhóm VIP kéo 1-1 chuyên gia tài chính bao lỗ 100%, nạp vốn 4 triệu để kích hoạt tín hiệu giao dịch.", 75),

    # 2. Mượn tiền / nick bạn bị hack
    ("chk_borrow_01", "Bạn ơi tài khoản ngân hàng của mình đang bị lỗi chuyển tiền, bạn chuyển gấp hộ mình 2 triệu vào stk này tí mình bắn lại.", 75),
    ("chk_borrow_02", "Mày ơi tao kẹt tiền đóng tiền viện phí gấp cho người nhà, bắn cho tao mượn 3 triệu chiều nhận lương tao trả.", 75),
    ("chk_borrow_03", "Chị ơi cho em mượn tạm 1 triệu thanh toán tiền hàng với ạ, tối về nhà em chuyển khoản trả lại chị ngay.", 75),
    ("chk_borrow_04", "Alo bạn, mình dùng số Zalo mới do máy cũ bị hỏng, đang có việc gấp bạn chuyển giúp mình 4 triệu mai mình gửi lại.", 75),
    ("chk_borrow_05", "Em ơi tài khoản anh hết hạn mức giao dịch trong ngày, chuyển hộ anh 2 triệu 500k vào stk này lát anh gửi lại tiền mặt.", 75),
    ("chk_borrow_06", "Mày hả tao đang ở trạm xăng mà quên mang ví, bắn gấp vào stk cây xăng 500k tí tao về nhà bắn lại cho.", 75),

    # 3. Tình cảm + chuyển tiền
    ("chk_romance_01", "Bạn trai làm việc ở giàn khoan ngoài biển bảo gửi kiện hàng quà tặng và tiền mặt về cho em, nhờ em nộp 7 triệu phí hải quan để nhận.", 75),
    ("chk_romance_02", "Anh quen em qua Tinder, anh gửi quà từ nước ngoài về cho em rồi, hải quan gọi bảo đóng phí vận chuyển quốc tế 5 triệu.", 75),
    ("chk_romance_03", "Người yêu ngoại quốc gửi thùng quà sinh nhật có ngoại tệ USD về Việt Nam, công ty vận chuyển yêu cầu nộp lệ phí sân bay 8 triệu.", 75),
    ("chk_romance_04", "Anh bạn quen trên mạng bảo gửi gói quà làm quen từ Mỹ về, nhờ em chuyển khoản nộp thuế thông quan vào tài khoản cá nhân.", 75),
    ("chk_romance_05", "Em quen một phi công nước ngoài gửi vali tiền tiết kiệm về nhờ em giữ hộ, bên lưu kho yêu cầu đóng 12 triệu phí giải phóng kiện hàng.", 75),
    ("chk_romance_06", "Bạn trai online gửi kiện bưu phẩm quà tặng đắt tiền về nước, bên chuyển phát thông báo cần đóng 4 triệu tiền phạt chậm thông quan.", 75),

    # 4. Giả OTP / khóa tài khoản
    ("chk_bank_otp_01", "VietinBank thông báo: Tài khoản của quý khách có dấu hiệu gian lận, truy cập http://vietinbank-security.xyz để xác thực ngay.", 75),
    ("chk_bank_otp_02", "VPBank cảnh báo: Thẻ của bạn bị khóa vĩnh viễn trong 24h, vui lòng truy cập https://vpbank-ebank.top để mở khóa.", 75),
    ("chk_bank_otp_03", "Ngân hàng Sacombank: Phát hiện truy cập trái phép, đọc mã OTP và số thẻ cho nhân viên trực tổng đài để hủy giao dịch.", 75),
    ("chk_bank_otp_04", "SHB thông báo tài khoản bị phong tỏa do chưa cập nhật CCCD gắn chip, vào link https://shb-smart.xyz để định danh.", 75),
    ("chk_bank_otp_05", "Nhân viên chăm sóc khách hàng ngân hàng gọi điện yêu cầu cung cấp 6 số mã OTP để hỗ trợ nâng cấp hạn mức thẻ tín dụng.", 75),
    ("chk_bank_otp_06", "VIB thông báo thẻ ghi nợ tạm dừng hoạt động, đăng nhập vào http://vib-portal.xyz trong 2 giờ để tiếp tục sử dụng.", 75),

    # 5. Bill giả / hoàn tiền
    ("chk_fake_bill_01", "Người mua gửi hình ảnh hóa đơn VietinBank đã chuyển khoản 3 triệu thành công nhưng số dư app chưa tăng, ép giao hàng ngay.", 75),
    ("chk_fake_bill_02", "Khách hàng gửi bill thanh toán VietQR báo thành công 4 triệu, bảo do khác ngân hàng nên tiền về chậm và giục giao xe.", 75),
    ("chk_fake_bill_03", "Tài khoản bỗng nhận được 5 triệu từ người lạ, sau đó có người gọi bảo chuyển nhầm và gửi link lạ yêu cầu nhấn vào để trả lại tiền.", 75),
    ("chk_fake_bill_04", "Bên mua gửi ảnh biên lai ngân hàng báo chuyển tiền hoàn tất nhưng kiểm tra tài khoản chưa có ting ting, hối gửi hàng đi.", 75),
    ("chk_fake_bill_05", "Khách chụp màn hình giao dịch chuyển khoản thành công nhưng tài khoản ngân hàng chưa báo tiền về, dọa hủy đơn và tố cáo shop.", 75),
    ("chk_fake_bill_06", "Đối tượng dàn cảnh gửi bill chuyển khoản giả mạo 6 triệu mua điện thoại và giục chủ cửa hàng đưa máy trước khi tiền về.", 75),

    # 6. Cho vay online / phí giải ngân
    ("chk_loan_01", "Khoản vay tiêu dùng 60 triệu của quý khách đã được phê duyệt, nộp phí thẩm định hồ sơ 2 triệu vào stk để giải ngân về tài khoản.", 75),
    ("chk_loan_02", "Hồ sơ vay tiền nhanh báo lỗi sai thông tin tài khoản, yêu cầu chuyển 4 triệu tiền đối ứng bảo lãnh để mở khóa khoản vay.", 75),
    ("chk_loan_03", "Duyệt vay cấp tốc 80 triệu không thế chấp, yêu cầu đóng trước 3 triệu phí bảo hiểm rủi ro tín dụng trước khi nhận tiền.", 75),
    ("chk_loan_04", "Khoản vay cá nhân online đã sẵn sàng giải ngân, khách hàng cần chuyển khoản nộp phí hợp đồng 1 triệu 500k để nhận mã giải ngân.", 75),
    ("chk_loan_05", "Hệ thống duyệt gói vay nóng 40 triệu, yêu cầu nộp tiền cọc giải ngân 2 triệu vào tài khoản cán bộ thẩm định để nhận tiền.", 75),
    ("chk_loan_06", "Thông báo hồ sơ vay 100 triệu bị treo do điểm tín dụng thấp, chuyển 5 triệu chứng minh năng lực tài chính để hoàn tất giải ngân.", 75),

    # 7. Giả shipper / hải quan
    ("chk_shipper_01", "Shipper gọi báo đơn hàng quần áo của bạn bị thiếu phí ship 60k, yêu cầu chuyển khoản ngay vào stk cá nhân để được giao hàng.", 75),
    ("chk_shipper_02", "Bưu tá VNPost báo kiện hàng gửi đến cơ quan bị giữ lại do chưa nộp thuế giá trị gia tăng, nộp phí 150k vào stk shipper.", 75),
    ("chk_shipper_03", "Cơ quan hải quan bưu điện thông báo bưu phẩm từ nước ngoài bị tạm giữ, chuyển 2 triệu vào số tài khoản cá nhân để thông quan.", 75),
    ("chk_shipper_04", "Shipper giao hàng J&T gọi thông báo gói hàng COD 200k đã gửi người quen nhận hộ, yêu cầu ck gấp tiền hàng vào stk riêng.", 75),
    ("chk_shipper_05", "Nhân viên bưu cục gọi thông báo bưu phẩm bị phạt cước lưu kho 300k, yêu cầu thanh toán chuyển khoản trước vào stk cá nhân.", 75),
    ("chk_shipper_06", "Shipper thông báo hàng giao không thành công do sai địa chỉ, yêu cầu nộp thêm phí chuyển phát lại 50k vào tài khoản cá nhân.", 75),

    # 8. Tuyển CTV / việc nhẹ lương cao
    ("chk_ctv_01", "Tuyển cộng tác viên xử lý đơn hàng Shopee tại nhà lương 600k/ngày, yêu cầu đặt cọc nạp tiền kích hoạt tài khoản đại lý 500k.", 75),
    ("chk_ctv_02", "Công việc online đánh giá sản phẩm sàn Lazada nhận hoa hồng 25%, làm nhiệm vụ chuyển tiền thanh toán đơn hàng trước.", 75),
    ("chk_ctv_03", "Cần tuyển ctv like video thả tim Tiktok kiếm tiền, nộp phí bảo đảm công việc 300k trên nhóm Telegram để nhận nhiệm vụ.", 75),
    ("chk_ctv_04", "Tuyển người làm việc online chốt đơn ảo tại nhà kiếm 700k/ngày, nộp tiền cọc giữ chỗ và nạp quỹ nhiệm vụ 400k.", 75),
    ("chk_ctv_05", "Việc nhẹ lương cao tuyển cộng tác viên nhập mã đơn hàng Tiki, yêu cầu chuyển khoản nộp phí đăng ký tài khoản 350k.", 75),
    ("chk_ctv_06", "Tuyển ctv tăng tương tác bài viết nhận lương theo giờ, yêu cầu đóng phí tham gia nhóm nhiệm vụ VIP 500k.", 75),

    # 9. Deepfake video call
    ("chk_deepfake_01", "Cuộc gọi video call mặt bạn bè bị mờ giật lag rồi ngắt kết nối sau 3 giây, sau đó nhắn tin qua Zalo nhờ chuyển tiền gấp 4 triệu.", 75),
    ("chk_deepfake_02", "Gọi video thấy hình người thân nhưng cử động mồm không khớp tiếng rè rè tắt máy ngay, nhắn tin bảo đang ở viện mượn 5 triệu.", 75),
    ("chk_deepfake_03", "Video call chập chờn nhòe nhoẹt chỉ thấy loáng thoáng khuôn mặt rồi tắt phụt, sau đó nhắn tin gấp nhờ chuyển khoản hộ tiền hàng.", 75),
    ("chk_deepfake_04", "Bạn học cũ gọi video thấy mặt nhưng mắt đơ không chớp mấy giây là cúp, nhắn tin bảo tài khoản ngân hàng bị khóa nhờ bắn giúp 3 triệu.", 75),
    ("chk_deepfake_05", "Cuộc gọi video call hình ảnh bị vỡ hạt giọng nói kỳ lạ tắt máy rất nhanh, nhắn tin bảo đang bị công an giữ xe cần chuyển 2 triệu.", 75),
    ("chk_deepfake_06", "Gọi video Zalo thấy mặt anh họ mờ tịt vài giây rồi bảo mạng kém tắt máy, nhắn tin nhờ chuyển gấp 6 triệu vào stk lạ.", 75),

    # 10. Hỗ trợ kỹ thuật / điều khiển từ xa
    ("chk_tech_01", "Chuyên viên IT gọi báo máy tính cá nhân bị cài mã độc đào tiền ảo, yêu cầu mở phần mềm TeamViewer và cấp quyền điều khiển từ xa.", 75),
    ("chk_tech_02", "Bộ phận an ninh mạng thông báo điện thoại của bạn bị nhiễm phần mềm gián điệp, tải Ultraviewer để kỹ thuật viên quét và diệt virus.", 75),
    ("chk_tech_03", "Hỗ trợ kỹ thuật ứng dụng ngân hàng yêu cầu khách hàng cài đặt AnyDesk trên máy tính để chuyên viên can thiệp xử lý lỗi giao dịch.", 75),
    ("chk_tech_04", "Kỹ thuật viên Microsoft gọi cảnh báo máy tính phát tán thư rác độc hại, yêu cầu cài RustDesk và đọc mã kết nối để hỗ trợ.", 75),
    ("chk_tech_05", "Bộ phận kỹ thuật dịch vụ công yêu cầu người dùng bật quyền trợ năng và cài ứng dụng điều khiển từ xa để sửa lỗi hồ sơ.", 75),
    ("chk_tech_06", "Nhân viên an toàn thông tin gọi điện cảnh báo tài khoản bị tấn công brute force, yêu cầu cài QuickSupport để chuyên viên khắc phục.", 75),

    # 11. Giả CSKH TMĐT
    ("chk_ecom_01", "Nhân viên CSKH Lazada gọi thông báo bạn đã trúng thưởng phiếu mua sắm 20 triệu, yêu cầu nộp 2 triệu tiền thuế vào stk để nhận quà.", 75),
    ("chk_ecom_02", "Tổng đài hỗ trợ Shopee gọi báo quý khách bị hệ thống tự động trừ phí thành viên VIP 4 triệu, hướng dẫn chuyển tiền để hoàn lại.", 75),
    ("chk_ecom_03", "CSKH TikTok Shop thông báo đơn hàng của bạn bị thất lạc và được bồi thường gấp đôi, yêu cầu nạp tiền đối ứng vào sàn để nhận tiền.", 75),
    ("chk_ecom_04", "Tổng đài viên Tiki gọi thông báo tài khoản người mua có tranh chấp khiếu nại, yêu cầu nộp tiền ký quỹ bảo đảm 3 triệu.", 75),
    ("chk_ecom_05", "Bộ phận CSKH Sendo báo đơn hàng bị thanh toán lỗi trừ tiền 2 lần, yêu cầu cung cấp thông tin thẻ ngân hàng để hoàn tiền.", 75),
    ("chk_ecom_06", "CSKH Shopee thông báo tài khoản gian hàng bị khóa tạm thời do nghi ngờ vi phạm, yêu cầu đóng phạt 5 triệu để kích hoạt lại.", 75),
]


# =============================================================================
# CHECK DATASET: 6 DIFFICULT BENIGN CATEGORIES (>= 6 SAMPLES EACH)
# =============================================================================
CHECK_BENIGN_SAMPLES = [
    # 1. Báo chí tường thuật
    ("chk_news_01", "Báo điện tử Dân trí phản ánh thủ đoạn lừa đảo việc nhẹ lương cao dụ dỗ người tìm việc nạp tiền làm nhiệm vụ.", 40),
    ("chk_news_02", "Theo báo Tuổi Trẻ, cơ quan công an vừa triệt phá một đường dây lừa đảo mạo danh shipper thu tiền cước qua mạng.", 40),
    ("chk_news_03", "Báo VnExpress đưa phóng sự điều tra về các ổ nhóm lừa đảo đầu tư sàn tài chính ảo núp bóng chuyên gia kéo lệnh.", 40),
    ("chk_news_04", "Báo Thanh Niên cảnh báo người dân về các vụ án lừa đảo chiếm đoạt tài sản bằng công nghệ deepfake video call giả mạo.", 40),
    ("chk_news_05", "Bản tin truyền hình An ninh mạng phát sóng phóng sự về chiêu trò giả mạo tin nhắn thông báo khóa tài khoản ngân hàng.", 40),
    ("chk_news_06", "Báo Lao Động đưa tin cơ quan điều tra đã khởi tố vụ án lừa đảo mạo danh cán bộ thuế yêu cầu cài đặt phần mềm độc hại.", 40),

    # 2. Công an / ngân hàng cảnh báo
    ("chk_warning_01", "Công an quận khuyến cáo người dân cảnh giác với các cuộc gọi xưng là cơ quan điều tra yêu cầu chuyển tiền vào tài khoản an toàn.", 40),
    ("chk_warning_02", "Ngân hàng BIDV khuyến cáo khách hàng tuyệt đối không cung cấp mật khẩu, mã OTP và thông tin thẻ cho bất kỳ đối tượng nào.", 40),
    ("chk_warning_03", "Cục An toàn thông tin phát cảnh báo về các trang web giả mạo giao diện ngân hàng nhằm đánh cắp thông tin đăng nhập của người dùng.", 40),
    ("chk_warning_04", "VietinBank gửi thông báo cảnh giác: Ngân hàng không bao giờ yêu cầu khách hàng bấm vào đường link lạ để xác thực thông tin.", 40),
    ("chk_warning_05", "Công an phường phát tờ rơi khuyến cáo người dân nâng cao tinh thần cảnh giác trước các thủ đoạn lừa đảo mượn tiền qua mạng.", 40),
    ("chk_warning_06", "Ngân hàng MB Bank cảnh báo thủ đoạn lừa đảo giả danh nhân viên chăm sóc khách hàng sàn thương mại điện tử gọi điện hoàn tiền.", 40),

    # 3. Người vừa bị lừa hỏi lời khuyên
    ("chk_victim_01", "Em vừa bị lừa chuyển 10 triệu vào sàn đầu tư tiền ảo thì có làm đơn tố giác tội phạm gửi công an huyện được không ạ?", 40),
    ("chk_victim_02", "Tôi bị kẻ gian lừa mất 20 triệu qua mạng, xin hỏi thủ tục nộp đơn báo án lên cơ quan điều tra cần những giấy tờ gì?", 40),
    ("chk_victim_03", "Mọi người cho mình hỏi nếu bị lừa chuyển khoản vào tài khoản mạo danh người quen thì có cơ hội lấy lại tiền không?", 40),
    ("chk_victim_04", "Em bị lừa cọc tiền nhận bưu phẩm quà tặng từ nước ngoài gửi về, giờ em phải làm thế nào để trình báo công an?", 40),
    ("chk_victim_05", "Cho em hỏi kinh nghiệm xử lý khi lỡ chuyển tiền cho bên tuyển dụng lừa đảo, có nên liên hệ ngân hàng phong tỏa ngay không?", 40),
    ("chk_victim_06", "Bị đối tượng mạo danh công an dọa nộp phạt chiếm đoạt tiền thì nộp đơn tố cáo tại công an nơi cư trú hay ở đâu ạ?", 40),

    # 4. Chat đời thường nhắc tiền
    ("chk_daily_01", "Bạn ơi mình vừa chuyển khoản 150k tiền vé xem phim tối nay rồi nhé, cảm ơn bạn nhiều nha.", 40),
    ("chk_daily_02", "Mày chuyển tiền ăn tối 80k hôm qua vào stk Vietcombank cho tao nhé, cảm ơn mày.", 40),
    ("chk_daily_03", "Chị đã nhận được tiền phòng trọ và tiền điện nước tháng này của em rồi nhé, cảm ơn em.", 40),
    ("chk_daily_04", "Tôi vừa chuyển khoản tiền mua giỏ trái cây biếu sinh nhật bạn rồi nhé, kiểm tra tài khoản giúp tôi.", 40),
    ("chk_daily_05", "Em gửi lại anh tiền xăng xe đi chung tuần trước 100k rồi nhé anh ơi, tiền về chưa ạ.", 40),
    ("chk_daily_06", "Bắn tiền trà sữa 35k lúc nãy cho tao nhé, tí tao thanh toán luôn cho cả nhóm.", 40),

    # 5. OTP / biến động số dư thật
    ("chk_otp_01", "Vietcombank thông báo số dư tài khoản 0123456789 thay đổi +5.000.000 VND lúc 14:20. Nội dung: Cong ty tra luong thang 9.", 40),
    ("chk_otp_02", "Techcombank: Mã OTP của bạn là 654321 để xác nhận thanh toán tiền điện. Tuyệt đối không cung cấp mã này cho người khác.", 40),
    ("chk_otp_03", "BIDV: Biến động số dư tài khoản 9876543210 -150.000 VND lúc 09:30. Nội dung: Thanh toan cuoc internet thang 10.", 40),
    ("chk_otp_04", "ACB thông báo: Tài khoản của quý khách vừa nhận 2.000.000 VND lúc 16:45. Nội dung: Ban Nguyen Van A chuyen tien mua hang.", 40),
    ("chk_otp_05", "Mã xác thực OTP của quý khách là 432156 để đăng nhập ứng dụng VNeID. Mã có hiệu lực trong vòng 3 phút.", 40),
    ("chk_otp_06", "VPBank: Quý khách vừa thanh toán thành công 320.000 VND tại siêu thị WinMart. Số dư khả dụng là 8.650.000 VND.", 40),

    # 6. Hỏi cách phòng chống
    ("chk_inquiry_01", "Làm thế nào để nhận biết và phòng tránh các cuộc gọi lừa đảo mạo danh nhân viên ngân hàng hỗ trợ nâng hạn mức thẻ?", 40),
    ("chk_inquiry_02", "Cho em hỏi những dấu hiệu đặc trưng để phân biệt giữa trang web chính thức của ngân hàng và trang web phishing lừa đảo?", 40),
    ("chk_inquiry_03", "Làm sao để phòng ngừa nguy cơ bị chiếm quyền điều khiển điện thoại từ xa qua các ứng dụng độc hại?", 40),
    ("chk_inquiry_04", "Hướng dẫn các bước cần làm ngay lập tức khi phát hiện tài khoản ngân hàng của mình có dấu hiệu bị lộ thông tin bảo mật.", 40),
    ("chk_inquiry_05", "Kinh nghiệm phòng chống chiêu trò lừa đảo chuyển nhầm tiền vào tài khoản rồi yêu cầu hoàn trả sang tài khoản khác.", 40),
    ("chk_inquiry_06", "Làm thế nào để kiểm tra tính xác thực của một đơn hàng bưu kiện trước khi quyết định thanh toán tiền COD cho shipper?", 40),
]


# =============================================================================
# FIXTURES
# =============================================================================
@pytest.fixture(scope="module")
def agent():
    return ExplainableAgent()


# =============================================================================
# DEV TEST SUITE: 100% PASS REQUIRED
# =============================================================================
@pytest.mark.parametrize("case_id,text,min_score", DEV_SCAM_SAMPLES, ids=[c[0] for c in DEV_SCAM_SAMPLES])
def test_dev_scam_family_coverage_high(agent, case_id, text, min_score):
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    score = res["risk_score"]
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert score >= min_score, f"[{case_id}] Expected >= {min_score}, got {score}. Factors: {factors}"


@pytest.mark.parametrize("case_id,text,max_score", DEV_BENIGN_SAMPLES, ids=[c[0] for c in DEV_BENIGN_SAMPLES])
def test_dev_benign_coverage_low(agent, case_id, text, max_score):
    res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
    score = res["risk_score"]
    factors = [f["factor"] for f in res["risk_breakdown"]]
    assert score < max_score, f"[{case_id}] Expected < {max_score}, got {score}. Factors: {factors}"


# =============================================================================
# CHECK TEST SUITE: >= 60% PASS REQUIRED
# =============================================================================
def test_check_suite_aggregate_pass_rate(agent):
    """
    Evaluates the separate check dataset (66 scam + 36 benign = 102 samples).
    Requires aggregate pass rate >= 60%.
    """
    passed = 0
    total = len(CHECK_SCAM_SAMPLES) + len(CHECK_BENIGN_SAMPLES)
    details = []

    for cid, text, min_score in CHECK_SCAM_SAMPLES:
        res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
        score = res["risk_score"]
        ok = score >= min_score
        if ok:
            passed += 1
        else:
            details.append(f"FAIL SCAM {cid}: score={score} < {min_score}")

    for cid, text, max_score in CHECK_BENIGN_SAMPLES:
        res = agent.explain(text, matched_flags=[], ocr_anomalies=[])
        score = res["risk_score"]
        ok = score < max_score
        if ok:
            passed += 1
        else:
            details.append(f"FAIL BENIGN {cid}: score={score} >= {max_score}")

    pass_rate = (passed / total) * 100.0
    print(f"\n[CHECK SUITE RESULT] Passed: {passed}/{total} ({pass_rate:.1f}%)")
    if details:
        print("Failures:")
        for d in details[:10]:
            print("  ", d)

    assert pass_rate >= 60.0, f"Check pass rate {pass_rate:.1f}% < 60% requirement"
