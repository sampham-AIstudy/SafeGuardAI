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
