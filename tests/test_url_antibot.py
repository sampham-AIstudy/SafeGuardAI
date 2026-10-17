import time
import pytest
from codebase.url_analysis.antibot import AntiBotResult, classify_response


def test_antibot_result_dataclass():
    res = AntiBotResult(vendor="cloudflare", kind="challenge", evidence=["ev1"])
    assert res.vendor == "cloudflare"
    assert res.kind == "challenge"
    assert res.evidence == ["ev1"]
    d = res.to_dict()
    assert d == {"vendor": "cloudflare", "kind": "challenge", "evidence": ["ev1"]}


# ============================================================================
# POSITIVE TESTS: >= 2 samples per vendor
# ============================================================================


def test_cloudflare_header_cf_mitigated():
    headers = {"cf-mitigated": "challenge", "server": "cloudflare"}
    body = "<html><body>Some content</body></html>"
    res = classify_response(403, headers, body)
    assert res is not None
    assert res.vendor == "cloudflare"
    assert res.kind == "challenge"
    assert any("cf-mitigated" in e for e in res.evidence)


def test_cloudflare_turnstile():
    body = '<div class="cf-turnstile" data-sitekey="0x4AAAAAA"></div>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "cloudflare"
    assert res.kind == "captcha"
    assert "body:cf-turnstile" in res.evidence


def test_cloudflare_challenges_platform():
    body = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "cloudflare"
    assert res.kind in ("challenge", "captcha")


def test_cloudflare_just_a_moment_challenge():
    headers = {"server": "cloudflare"}
    body = "<title>Just a moment...</title><p>Checking your browser before accessing example.com</p>"
    res = classify_response(503, headers, body)
    assert res is not None
    assert res.vendor == "cloudflare"
    assert res.kind == "challenge"


def test_cloudflare_error_1020_block():
    headers = {"server": "cloudflare"}
    body = "<h1>Error 1020: Access denied</h1><p>Ray ID: 123456</p>"
    res = classify_response(403, headers, body)
    assert res is not None
    assert res.vendor == "cloudflare"
    assert res.kind == "block"


def test_recaptcha_script_and_widget():
    body = """
    <html>
      <head><script src="https://www.google.com/recaptcha/api.js" async defer></script></head>
      <body><div class="g-recaptcha" data-sitekey="6Le-w-fake"></div></body>
    </html>
    """
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "recaptcha"
    assert res.kind == "captcha"


def test_recaptcha_enterprise():
    body = """
    <script src="https://www.google.com/recaptcha/enterprise.js?render=6Lf-fake"></script>
    <script>grecaptcha.enterprise.ready(function(){});</script>
    """
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "recaptcha"
    assert res.kind == "captcha"


def test_hcaptcha_script_and_widget():
    body = """
    <html>
      <head><script src="https://js.hcaptcha.com/1/api.js" async defer></script></head>
      <body><div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div></body>
    </html>
    """
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "hcaptcha"
    assert res.kind == "captcha"


def test_hcaptcha_api_script():
    body = '<script src="https://hcaptcha.com/1/api.js"></script>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "hcaptcha"
    assert res.kind == "captcha"


def test_datadome_header():
    headers = {"x-datadome": "protected", "x-datadome-response": "403"}
    res = classify_response(403, headers, "Blocked by DataDome")
    assert res is not None
    assert res.vendor == "datadome"
    assert res.kind in ("block", "challenge")


def test_datadome_body_token():
    body = '<script src="https://js.datadome.co/tags.js"></script><script>dd_cookie_test=1;</script>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "datadome"
    assert res.kind == "challenge"


def test_perimeterx_captcha():
    body = '<div id="px-captcha"></div><script src="https://client.perimeterx.net/PX1234/main.min.js"></script>'
    res = classify_response(403, {}, body)
    assert res is not None
    assert res.vendor == "perimeterx"
    assert res.kind == "captcha"


def test_perimeterx_token():
    body = '<script>window._pxhd = "abcd1234efgh";</script>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "perimeterx"
    assert res.kind == "challenge"


def test_incapsula_resource():
    body = '<script src="/_Incapsula_Resource?SWJIYLWA=719d34eb"></script>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "incapsula"
    assert res.kind == "challenge"


def test_incapsula_headers():
    headers = {"x-iinfo": "12-345678-9", "x-cdn": "Imperva"}
    res = classify_response(403, headers, "Request blocked by Imperva")
    assert res is not None
    assert res.vendor == "incapsula"
    assert res.kind in ("block", "challenge")


def test_akamai_ghost_server():
    headers = {"server": "AkamaiGHost"}
    body = "<h1>Access Denied</h1><p>You don't have permission to access.</p>"
    res = classify_response(403, headers, body)
    assert res is not None
    assert res.vendor == "akamai"
    assert res.kind == "block"


def test_akamai_reference_code():
    body = "<h1>Access Denied</h1><p>Reference #18.12345.67890.abcdef</p>"
    res = classify_response(403, {}, body)
    assert res is not None
    assert res.vendor == "akamai"
    assert res.kind == "block"


def test_sucuri_header():
    headers = {"x-sucuri-id": "18012"}
    body = "Website Firewall - Access Denied"
    res = classify_response(403, headers, body)
    assert res is not None
    assert res.vendor == "sucuri"
    assert res.kind in ("block", "challenge")


def test_sucuri_cloudproxy_body():
    body = "<h2>Sucuri WebSite Firewall - CloudProxy - Access Denied</h2>"
    res = classify_response(403, {}, body)
    assert res is not None
    assert res.vendor == "sucuri"
    assert res.kind == "block"


def test_awswaf_header_captcha():
    headers = {"x-amzn-waf-action": "captcha"}
    res = classify_response(405, headers, "")
    assert res is not None
    assert res.vendor == "awswaf"
    assert res.kind == "captcha"


def test_awswaf_header_challenge():
    headers = {"x-amzn-waf-action": "challenge"}
    res = classify_response(202, headers, "")
    assert res is not None
    assert res.vendor == "awswaf"
    assert res.kind == "challenge"


def test_generic_phrase_en():
    body = "<div>Please verify you are human to proceed to the website.</div>"
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind in ("captcha", "challenge")


def test_generic_phrase_vi_xac_minh():
    body = "<div>Vui lòng xác minh bạn là người để tiếp tục.</div>"
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind in ("captcha", "challenge")


def test_generic_phrase_vi_kiem_tra_trinh_duyet():
    body = "<div>Đang kiểm tra trình duyệt của bạn trước khi truy cập...</div>"
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "challenge"


def test_generic_phrase_enable_javascript():
    body = "<p>Please enable javascript to continue.</p>"
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "challenge"


def test_js_only_redirect():
    body = '<script>window.location.replace("https://dest.example.com");</script><noscript>Redirecting</noscript>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "js_only"


def test_js_only_location_href():
    body = '<script>location.href = "/target";</script>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "js_only"


def test_interstitial_click_to_continue():
    body = "<button>Click to continue</button>"
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "interstitial"


def test_interstitial_nhan_de_tiep_tuc():
    body = '<a href="/next">Nhấn để tiếp tục</a>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "interstitial"


def test_interstitial_adfly():
    body = '<div class="adfly_skip"><a href="#">Skip AD</a></div>'
    res = classify_response(200, {}, body)
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "interstitial"


def test_generic_403_short_body():
    res = classify_response(403, {}, "<html><body><h1>403 Forbidden</h1></body></html>")
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "block"


def test_generic_403_empty_body():
    res = classify_response(403, {}, "")
    assert res is not None
    assert res.vendor == "generic"
    assert res.kind == "block"


# ============================================================================
# NEGATIVE TESTS: >= 12 negative samples returning None
# ============================================================================


def test_neg_cloudflare_200_normal_site():
    headers = {"server": "cloudflare", "content-type": "text/html; charset=utf-8"}
    body = """
    <!DOCTYPE html>
    <html>
      <head><title>Trang tin tức tổng hợp</title></head>
      <body>
        <h1>Chào mừng bạn đến với chuyên trang công nghệ</h1>
        <p>Hôm nay chúng ta cùng thảo luận về kiến trúc phần mềm phân tán và các mô hình microservices hiện đại.</p>
        <p>Hệ thống hoạt động ổn định và đáp ứng hàng triệu người dùng mỗi ngày.</p>
      </body>
    </html>
    """
    res = classify_response(200, headers, body)
    assert res is None


def test_neg_standard_404_not_found():
    headers = {"server": "nginx"}
    body = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1>The requested URL was not found on this server.</body></html>"
    res = classify_response(404, headers, body)
    assert res is None


def test_neg_news_article_mentioning_captcha():
    headers = {"server": "cloudflare"}
    body = """
    <article>
      <h1>Hướng dẫn bảo mật biểu mẫu website</h1>
      <p>Khi xây dựng form đăng ký, lập trình viên thường dùng captcha để chống bot và hạn chế việc gửi dữ liệu tự động hàng loạt.</p>
      <p>Các phương pháp bảo mật phổ biến bao gồm rate limiting, honeypot field và kiểm tra IP bất thường.</p>
    </article>
    """
    res = classify_response(200, headers, body)
    assert res is None


def test_neg_tutorial_article_mentioning_recaptcha():
    body = """
    <article>
      <h1>So sánh các giải pháp phòng chống spam</h1>
      <p>reCAPTCHA là một giải pháp quen thuộc do Google phát triển. Bên cạnh đó, quản trị viên cũng có thể sử dụng Cloudflare hoặc giải pháp tự phát triển.</p>
      <p>Việc lựa chọn phụ thuộc vào yêu cầu về quyền riêng tư và trải nghiệm người dùng.</p>
    </article>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_tech_news_mentioning_cloudflare():
    headers = {"server": "apache"}
    body = """
    <main>
      <h1>Cloudflare công bố báo cáo an ninh mạng quý 3</h1>
      <p>Báo cáo ghi nhận sự gia tăng của các đợt tấn công DDoS nhắm vào dịch vụ tài chính tại khu vực châu Á.</p>
    </main>
    """
    res = classify_response(200, headers, body)
    assert res is None


def test_neg_ecommerce_homepage_200():
    body = """
    <html>
      <head><title>Cửa hàng thời trang online</title></head>
      <body>
        <header><nav><a href="/ao">Áo</a><a href="/quan">Quần</a></nav></header>
        <section><h2>Sản phẩm nổi bật</h2><p>Bộ sưu tập mùa thu mới nhất với ưu đãi 20% toàn bộ đơn hàng.</p></section>
      </body>
    </html>
    """
    res = classify_response(200, {"server": "nginx/1.22"}, body)
    assert res is None


def test_neg_bank_official_login_page_200():
    body = """
    <html>
      <head><title>Ngân hàng số VCB Digibank</title></head>
      <body>
        <h1>Đăng nhập ngân hàng trực tuyến</h1>
        <form action="/login" method="post">
          <input type="text" name="username" placeholder="Tên đăng nhập">
          <input type="password" name="password" placeholder="Mật khẩu">
          <button type="submit">Đăng nhập</button>
        </form>
      </body>
    </html>
    """
    res = classify_response(200, {"server": "envoy"}, body)
    assert res is None


def test_neg_403_long_cms_permission_denied():
    body = "<html><body>" + ("<p>Chi tiết quyền truy cập bị hạn chế bởi chính sách của hệ thống quản trị nội bộ công ty.</p>" * 20) + "</body></html>"
    res = classify_response(403, {"server": "apache"}, body)
    assert res is None


def test_neg_vietnamese_security_blog_bot_protection():
    body = """
    <article>
      <h1>Kinh nghiệm triển khai bot protection</h1>
      <p>Một chiến lược bot protection hiệu quả cần kết hợp phân tích hành vi và lọc địa chỉ IP uy tín để không ảnh hưởng đến người dùng thực.</p>
      <p>Nhiều doanh nghiệp đã giảm thiểu đáng kể chi phí hạ tầng sau khi áp dụng các giải pháp chuyên dụng.</p>
    </article>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_500_server_error_django():
    body = "<html><head><title>Server Error (500)</title></head><body><h1>Server Error (500)</h1><p>An error occurred in Django application.</p></body></html>"
    res = classify_response(500, {}, body)
    assert res is None


def test_neg_302_redirect_with_location():
    headers = {"location": "https://example.com/login", "server": "nginx"}
    body = "<html><body>302 Found</body></html>"
    res = classify_response(302, headers, body)
    assert res is None


def test_neg_article_with_word_human():
    body = """
    <article>
      <h1>Triết học và trí tuệ nhân tạo</h1>
      <p>Câu hỏi đặt ra là điều gì thực sự làm nên bản chất của con người (human nature) trong kỷ nguyên máy học.</p>
    </article>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_valid_html_meta_refresh_redirect():
    body = '<html><head><meta http-equiv="refresh" content="0; url=https://target.com/home"></head></html>'
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_music_blog_skip_phrase():
    body = """
    <div>
      <h1>Đánh giá album âm nhạc mới</h1>
      <p>Nếu bạn không thích bài mở đầu, hãy skip bài 1 và nghe trực tiếp bài 2 với giai điệu mượt mà.</p>
    </div>
    """
    res = classify_response(200, {}, body)
    assert res is None


# ─────────────────────────────────────────────────────────────────────────────
# 16 REALISTIC NEGATIVE SAMPLES (S5b: News, forms, SPAs, tutorials)
# ─────────────────────────────────────────────────────────────────────────────

def test_neg_sample_1_news_click_to_continue_reading():
    body = """
    <html><head><title>Tin tức thời sự 24h</title></head>
    <body>
      <header><nav><a href="/">Trang chủ</a><a href="/kinh-doanh">Kinh doanh</a></nav></header>
      <article>
        <h1>Bản tin thị trường tài chính quốc tế ngày hôm nay</h1>
        <p>Thị trường chứng khoán khởi sắc trong phiên giao dịch đầu tuần với nhiều tín hiệu tích cực.</p>
        <p>""" + ("Dòng tiền lớn đổ vào nhóm cổ phiếu năng lượng tái tạo và công nghệ sinh học. " * 30) + """</p>
        <div class="read-more-wrapper"><button class="btn">Click to continue reading</button></div>
        <p>""" + ("Phân tích chi tiết của các chuyên gia kinh tế hàng đầu khu vực Đông Nam Á. " * 30) + """</p>
      </article>
      <footer><p>© 2026 Bản tin thời sự</p></footer>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_2_video_streaming_skip_ad():
    body = """
    <html><head><title>Video trực tuyến</title></head>
    <body>
      <div id="player-container">
        <video src="stream.mp4"></video>
        <div class="ad-overlay"><button id="skip-btn">Skip Ad</button></div>
      </div>
      <div class="video-info">
        <h2>Phim tài liệu khoa học tự nhiên vũ trụ</h2>
        <p>""" + ("Khám phá những bí ẩn của các vì sao xa xôi trong dải ngân hà của chúng ta. " * 40) + """</p>
      </div>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_3_registration_form_with_recaptcha():
    body = """
    <html><head><title>Đăng ký tài khoản thành viên</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    </head>
    <body>
      <h2>Tạo tài khoản mới</h2>
      <form action="/register" method="POST">
        <label>Họ và tên</label><input type="text" name="fullname" value="Nguyen Van A"><br>
        <label>Email</label><input type="email" name="email" value="user@example.com"><br>
        <label>Mật khẩu</label><input type="password" name="password"><br>
        <label>Số điện thoại</label><input type="tel" name="phone"><br>
        <label>Địa chỉ</label><input type="text" name="address"><br>
        <div class="g-recaptcha" data-sitekey="6Le-w-fake"></div>
        <button type="submit">Hoàn tất đăng ký</button>
      </form>
      <div class="terms">
        <p>""" + ("Bằng việc đăng ký, bạn đồng ý với các điều khoản dịch vụ và chính sách bảo mật của chúng tôi. " * 25) + """</p>
      </div>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_4_contact_us_form_with_hcaptcha():
    body = """
    <html><head><title>Liên hệ hỗ trợ khách hàng</title>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    </head>
    <body>
      <h1>Trung tâm hỗ trợ và giải đáp thắc mắc</h1>
      <form action="/contact" method="POST">
        <input type="text" name="company" placeholder="Tên doanh nghiệp">
        <input type="text" name="name" placeholder="Người liên hệ">
        <input type="email" name="email" placeholder="Email công việc">
        <textarea name="message" rows="5">Xin chào, tôi cần báo giá dịch vụ.</textarea>
        <div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
        <button type="submit">Gửi yêu cầu tư vấn</button>
      </form>
      <section>
        <p>""" + ("Đội ngũ kỹ sư hỗ trợ kỹ thuật trực tuyến 24/7 luôn sẵn sàng hỗ trợ giải đáp mọi thắc mắc. " * 30) + """</p>
      </section>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_5_long_article_discussing_bot_protection_and_verify():
    # Long article (> 8192 chars) discussing bot protection & verify
    content = """
    <html><head><title>Chiến lược bảo mật Web Application Firewall</title></head>
    <body>
      <article>
        <h1>Tìm hiểu các giải pháp Bot Protection hiện đại cho ứng dụng đám mây</h1>
        <p>Trong thời đại số, bot protection là lớp phòng vệ đầu tiên giúp giảm tải cho máy chủ web.</p>
        <p>Các hệ thống này thường verify tính hợp lệ của client thông qua HTTP header và TLS fingerprinting.</p>
        <section>
    """ + ("<p>Việc triển khai các rào chắn chống tấn công từ chối dịch vụ phân tán cần sự cân nhắc kỹ lưỡng để không làm giảm trải nghiệm của người dùng thực sự.</p>\n" * 90) + """
        </section>
      </article>
    </body></html>
    """
    assert len(content) > 8192
    res = classify_response(200, {}, content)
    assert res is None


def test_neg_sample_6_cybersecurity_news_on_anti_bot_bypass():
    content = """
    <html><head><title>Báo cáo An ninh Mạng Quý 3</title></head>
    <body>
      <h1>Phân tích các kỹ thuật né tránh hệ thống kiểm duyệt và Captcha</h1>
      <p>Báo cáo chỉ ra rằng tội phạm mạng liên tục tìm kiếm cách qua mặt các lớp bot challenge phổ biến.</p>
    """ + ("<p>Các tổ chức tài chính ngân hàng đang tăng cường xác thực đa yếu tố và phân tích hành vi thời gian thực.</p>\n" * 80) + """
    </body></html>
    """
    assert len(content) > 8192
    res = classify_response(200, {}, content)
    assert res is None


def test_neg_sample_7_minimal_spa_with_title():
    body = """
    <!DOCTYPE html>
    <html lang="vi">
    <head>
      <meta charset="utf-8">
      <title>Bảng điều khiển quản trị hệ thống</title>
      <link rel="stylesheet" href="/app.css">
    </head>
    <body>
      <div id="root"><header><h1>Trang chủ quản trị</h1></header></div>
      <script>
        if (!window.location.hash) { window.location.hash = '#/dashboard'; }
      </script>
    </body>
    </html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_8_react_landing_page_with_window_location():
    body = """
    <!DOCTYPE html>
    <html><head><title>Sản phẩm SaaS thông minh cho doanh nghiệp</title></head>
    <body>
      <div id="app">
        <h1>Giải pháp chuyển đổi số toàn diện</h1>
        <p>Tối ưu hóa quy trình làm việc và tự động hóa báo cáo doanh số.</p>
        <p>""" + ("Khám phá hệ sinh thái sản phẩm công nghệ tiên tiến phục vụ hàng triệu người dùng. " * 20) + """</p>
      </div>
      <script>
        var currentPath = window.location.pathname;
        console.log("Mounted on path: " + currentPath);
      </script>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_9_ecommerce_product_page():
    body = """
    <html><head><title>Điện thoại thông minh Flagship 2026</title></head>
    <body>
      <h1>Điện thoại thông minh cấu hình khủng 16GB RAM</h1>
      <p class="price">Giá ưu đãi: 19.990.000 VNĐ</p>
      <button class="buy-now">Mua ngay</button>
      <div class="desc">
        <p>""" + ("Màn hình OLED 120Hz siêu nét, camera góc rộng cảm biến Sony mới nhất. " * 30) + """</p>
      </div>
      <div class="reviews">
        <h3>Đánh giá từ khách hàng</h3>
        <p>Sản phẩm rất tốt, đóng gói cẩn thận, giao hàng nhanh chóng.</p>
      </div>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_10_banking_security_tips_page():
    body = """
    <html><head><title>Cẩm nang an toàn giao dịch ngân hàng điện tử</title></head>
    <body>
      <h1>Khuyến cáo bảo mật tài khoản trực tuyến</h1>
      <p>Ngân hàng không bao giờ yêu cầu khách hàng cung cấp mã OTP hoặc mật khẩu cá nhân.</p>
      <p>""" + ("Luôn kiểm tra kỹ địa chỉ trang web trước khi thực hiện giao dịch chuyển tiền. " * 35) + """</p>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_11_music_streaming_skip_track_blog():
    body = """
    <html><head><title>Tuyển tập nhạc không lời thư giãn</title></head>
    <body>
      <h1>Playlist nhạc tập trung làm việc hiệu quả</h1>
      <p>Nếu bạn muốn skip qua đoạn mở đầu chậm rãi, hãy chuyển thẳng sang bản giao hưởng số 5.</p>
      <p>""" + ("Giai điệu nhẹ nhàng êm dịu giúp kích thích tư duy sáng tạo và tăng năng suất. " * 30) + """</p>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_12_forum_thread_long_discussion():
    body = """
    <html><head><title>Diễn đàn công nghệ thông tin</title></head>
    <body>
      <h1>Thảo luận về các giải pháp CDN và lưu trữ phân tán</h1>
      <div class="post">
        <p>Chào các bạn, mình đang tìm kiếm giải pháp CDN tối ưu chi phí cho trang thương mại điện tử.</p>
      </div>
    """ + ("<div class='reply'><p>Theo kinh nghiệm của mình thì nên kết hợp nhiều nhà cung cấp để dự phòng sự cố mạng.</p></div>\n" * 80) + """
    </body></html>
    """
    assert len(body) > 8192
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_13_python_scraping_educational_guide():
    body = """
    <html><head><title>Hướng dẫn lập trình Python căn bản</title></head>
    <body>
      <h1>Xử lý dữ liệu web với BeautifulSoup và Requests</h1>
      <p>Trong bài viết này, chúng ta sẽ học cách phân tích cấu trúc DOM và trích xuất dữ liệu.</p>
    """ + ("<p>Luôn tuân thủ quy tắc robots.txt và giữ tần suất gửi request hợp lý để không gây quá tải máy chủ.</p>\n" * 80) + """
    </body></html>
    """
    assert len(body) > 8192
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_14_custom_branded_404_page():
    body = """
    <html><head><title>404 Không tìm thấy trang</title></head>
    <body>
      <h1>Rất tiếc! Trang bạn đang tìm kiếm không tồn tại</h1>
      <p>Địa chỉ liên kết có thể đã bị thay đổi hoặc xóa bỏ.</p>
      <a href="/">Quay về trang chủ</a> | <a href="/sitemap">Sơ đồ trang</a>
      <p>""" + ("Vui lòng kiểm tra lại đường dẫn hoặc liên hệ ban quản trị để được hỗ trợ. " * 25) + """</p>
    </body></html>
    """
    res = classify_response(404, {}, body)
    assert res is None


def test_neg_sample_15_corporate_about_us_page():
    body = """
    <html><head><title>Giới thiệu về tập đoàn công nghệ</title></head>
    <body>
      <h1>Lịch sử hình thành và tầm nhìn chiến lược</h1>
      <p>Được thành lập từ năm 2015, chúng tôi luôn tiên phong trong việc phát triển giải pháp AI.</p>
      <p>""" + ("Cam kết mang lại giá trị bền vững cho đối tác và cộng đồng doanh nghiệp Việt Nam. " * 30) + """</p>
      <h3>Đội ngũ sáng lập</h3>
      <p>Các chuyên gia giàu kinh nghiệm trong lĩnh vực khoa học máy tính và bảo mật thông tin.</p>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None


def test_neg_sample_16_government_portal_announcement():
    body = """
    <html><head><title>Cổng thông tin dịch vụ công trực tuyến</title></head>
    <body>
      <h1>Thông báo về việc nâng cấp hệ thống tiếp nhận hồ sơ hành chính</h1>
      <p>Hệ thống sẽ tạm dừng tiếp nhận hồ sơ trong khung giờ bảo trì từ 22h đến 24h.</p>
      <p>""" + ("Mọi thắc mắc vui lòng liên hệ tổng đài hỗ trợ người dân và doanh nghiệp theo số hotline. " * 30) + """</p>
    </body></html>
    """
    res = classify_response(200, {}, body)
    assert res is None



# ============================================================================
# REDOS AND PERFORMANCE BENCHMARK
# ============================================================================


def test_redos_repeated_keywords_under_100ms():
    pattern = "Just a moment... Checking your browser... verify you are human cf-chl " * 1000
    assert len(pattern) >= 60000

    headers = {"server": "nginx", "x-custom": "test"}

    t0 = time.perf_counter()
    res = classify_response(200, headers, pattern)
    elapsed = time.perf_counter() - t0

    assert elapsed < 0.1, f"Execution took {elapsed:.4f}s, expected < 0.1s"
    assert res is not None
