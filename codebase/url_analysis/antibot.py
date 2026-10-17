from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AntiBotResult:
    vendor: str
    kind: str  # 'challenge' | 'captcha' | 'block' | 'js_only' | 'interstitial'
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "kind": self.kind,
            "evidence": list(self.evidence),
        }


def classify_response(
    status: int | None,
    headers: dict[str, str] | None,
    body_snippet: str | bytes | None,
) -> AntiBotResult | None:
    """
    Classify an HTTP response to determine if it is an anti-bot challenge, captcha,
    WAF block, JS-only redirection, or shortener interstitial. Pure function, no I/O.

    Guarantees:
      - Linear execution time, bounded input, zero ReDoS risk.
      - False-positive resistance: standard Cloudflare 200, normal 404, or news articles
        mentioning captcha are not flagged.
    """
    headers_lower: dict[str, str] = {
        str(k).lower(): str(v) for k, v in (headers or {}).items()
    }

    if isinstance(body_snippet, (bytes, bytearray)):
        body_text = body_snippet[:65536].decode("utf-8", errors="replace")
    else:
        body_text = str(body_snippet or "")[:65536]
    body_lower = body_text.lower()

    # -------------------------------------------------------------
    # 1. Cloudflare
    # -------------------------------------------------------------
    cf_mitigated = headers_lower.get("cf-mitigated", "").lower()
    if "challenge" in cf_mitigated:
        return AntiBotResult(
            vendor="cloudflare",
            kind="challenge",
            evidence=["header:cf-mitigated:challenge"],
        )

    # Cloudflare Turnstile
    if "cf-turnstile" in body_lower or "challenges.cloudflare.com/turnstile" in body_lower:
        return AntiBotResult(
            vendor="cloudflare",
            kind="captcha",
            evidence=["body:cf-turnstile"],
        )

    # Cloudflare challenge platform / scripts
    if "challenges.cloudflare.com" in body_lower:
        return AntiBotResult(
            vendor="cloudflare",
            kind="challenge",
            evidence=["body:challenges.cloudflare.com"],
        )

    if "cf-chl" in body_lower or "cf_chl_" in body_lower:
        return AntiBotResult(
            vendor="cloudflare",
            kind="challenge",
            evidence=["body:cf_chl"],
        )

    server_hdr = headers_lower.get("server", "").lower()
    is_cloudflare_server = "cloudflare" in server_hdr

    # Cloudflare challenge body markers
    if "just a moment" in body_lower:
        if (
            is_cloudflare_server
            or "cloudflare" in body_lower
            or "browser" in body_lower
            or "ray id" in body_lower
        ):
            return AntiBotResult(
                vendor="cloudflare",
                kind="challenge",
                evidence=["body:just_a_moment"],
            )

    if "checking your browser" in body_lower:
        if (
            is_cloudflare_server
            or "cloudflare" in body_lower
            or "accessing" in body_lower
            or "ddos protection" in body_lower
        ):
            return AntiBotResult(
                vendor="cloudflare",
                kind="challenge",
                evidence=["body:checking_your_browser"],
            )

    # Cloudflare block on 403/429/503
    if is_cloudflare_server and status in (403, 429, 503):
        if any(
            marker in body_lower
            for marker in (
                "error 1020",
                "access denied",
                "ray id",
                "cf-ray",
                "1015",
                "1006",
                "blocked by cloudflare",
                "security by cloudflare",
            )
        ):
            return AntiBotResult(
                vendor="cloudflare",
                kind="block",
                evidence=[f"status:{status}", "server:cloudflare", "body:cloudflare_block"],
            )
        # Cloudflare short or empty error page on 403/429/503
        if len(body_text.strip()) < 512:
            return AntiBotResult(
                vendor="cloudflare",
                kind="block",
                evidence=[f"status:{status}", "server:cloudflare", "short_body"],
            )

    # -------------------------------------------------------------
    # 2. AWS WAF
    # -------------------------------------------------------------
    amzn_waf_action = headers_lower.get(
        "x-amzn-waf-action", headers_lower.get("x-amz-waf-action", "")
    ).lower()
    if amzn_waf_action:
        if "captcha" in amzn_waf_action:
            return AntiBotResult(
                vendor="awswaf",
                kind="captcha",
                evidence=["header:x-amzn-waf-action:captcha"],
            )
        elif "challenge" in amzn_waf_action:
            return AntiBotResult(
                vendor="awswaf",
                kind="challenge",
                evidence=["header:x-amzn-waf-action:challenge"],
            )
        elif "block" in amzn_waf_action:
            return AntiBotResult(
                vendor="awswaf",
                kind="block",
                evidence=["header:x-amzn-waf-action:block"],
            )

    if "awswaf" in body_lower and (
        "token" in body_lower
        or "captcha" in body_lower
        or "challenge" in body_lower
        or "aws-waf" in body_lower
    ):
        kind = "captcha" if "captcha" in body_lower else "challenge"
        return AntiBotResult(
            vendor="awswaf",
            kind=kind,
            evidence=["body:awswaf"],
        )

    # -------------------------------------------------------------
    # 3. DataDome
    # -------------------------------------------------------------
    if "x-datadome" in headers_lower or "x-datadome-response" in headers_lower:
        kind = "block" if status == 403 else "challenge"
        return AntiBotResult(
            vendor="datadome",
            kind=kind,
            evidence=["header:x-datadome"],
        )

    if "dd_cookie_test" in body_lower or "api.datadome.co" in body_lower:
        return AntiBotResult(
            vendor="datadome",
            kind="challenge",
            evidence=["body:datadome_token"],
        )

    if "datadome" in body_lower and (
        "datadome.js" in body_lower
        or "captcha" in body_lower
        or "blocked" in body_lower
        or status in (403, 429)
    ):
        kind = "block" if status == 403 else "challenge"
        return AntiBotResult(
            vendor="datadome",
            kind=kind,
            evidence=["body:datadome"],
        )

    # -------------------------------------------------------------
    # 4. PerimeterX / HUMAN
    # -------------------------------------------------------------
    if "px-captcha" in body_lower:
        return AntiBotResult(
            vendor="perimeterx",
            kind="captcha",
            evidence=["body:px-captcha"],
        )

    if "_pxhd" in body_lower or "_pxvid" in body_lower or "client.perimeterx.net" in body_lower:
        return AntiBotResult(
            vendor="perimeterx",
            kind="challenge",
            evidence=["body:perimeterx_token"],
        )

    if "perimeterx" in body_lower and (
        "challenge" in body_lower or "captcha" in body_lower or status in (403, 429)
    ):
        return AntiBotResult(
            vendor="perimeterx",
            kind="challenge",
            evidence=["body:perimeterx"],
        )

    # -------------------------------------------------------------
    # 5. Imperva / Incapsula
    # -------------------------------------------------------------
    if "x-iinfo" in headers_lower:
        return AntiBotResult(
            vendor="incapsula",
            kind="challenge",
            evidence=["header:x-iinfo"],
        )

    if "imperva" in headers_lower.get("x-cdn", "").lower():
        kind = "block" if status == 403 else "challenge"
        return AntiBotResult(
            vendor="incapsula",
            kind=kind,
            evidence=["header:x-cdn:imperva"],
        )

    if "_incapsula_resource" in body_lower or "incap_ses" in body_lower:
        return AntiBotResult(
            vendor="incapsula",
            kind="challenge",
            evidence=["body:incapsula_resource"],
        )

    # -------------------------------------------------------------
    # 6. Sucuri
    # -------------------------------------------------------------
    if "x-sucuri-id" in headers_lower or "x-sucuri-cache" in headers_lower:
        if status in (403, 429, 503) or "cloudproxy" in body_lower or "block" in body_lower:
            return AntiBotResult(
                vendor="sucuri",
                kind="block" if status == 403 else "challenge",
                evidence=["header:x-sucuri"],
            )

    if "sucuri" in body_lower and (
        "cloudproxy" in body_lower
        or "website firewall" in body_lower
        or "access denied - sucuri" in body_lower
    ):
        return AntiBotResult(
            vendor="sucuri",
            kind="block",
            evidence=["body:sucuri_firewall"],
        )

    # -------------------------------------------------------------
    # 7. Akamai
    # -------------------------------------------------------------
    if "akamaighost" in server_hdr:
        if status in (403, 429, 503) or "access denied" in body_lower:
            return AntiBotResult(
                vendor="akamai",
                kind="block",
                evidence=[f"status:{status}", "server:akamaighost"],
            )

    if "reference #" in body_lower and ("access denied" in body_lower or status == 403):
        if "akamaighost" in server_hdr or "akamai" in body_lower or status == 403:
            return AntiBotResult(
                vendor="akamai",
                kind="block",
                evidence=["body:akamai_reference"],
            )

    # -------------------------------------------------------------
    # 8. reCAPTCHA (Guarded against false positives on news/blogs)
    # -------------------------------------------------------------
    # Genuine reCAPTCHA challenge pages include widgets, api.js, or execution calls
    has_recaptcha_script = (
        "google.com/recaptcha/api.js" in body_lower
        or "google.com/recaptcha/enterprise.js" in body_lower
        or "www.recaptcha.net/recaptcha/api.js" in body_lower
    )
    has_recaptcha_widget = (
        "g-recaptcha" in body_lower
        and any(
            marker in body_lower
            for marker in ("class=", "id=", "data-sitekey", "grecaptcha.")
        )
    )
    if has_recaptcha_script or has_recaptcha_widget:
        return AntiBotResult(
            vendor="recaptcha",
            kind="captcha",
            evidence=["body:recaptcha_widget"],
        )

    # -------------------------------------------------------------
    # 9. hCaptcha (Guarded against false positives on news/blogs)
    # -------------------------------------------------------------
    has_hcaptcha_script = (
        "hcaptcha.com/1/api.js" in body_lower
        or "js.hcaptcha.com" in body_lower
    )
    has_hcaptcha_widget = (
        "h-captcha" in body_lower
        and any(
            marker in body_lower
            for marker in ("class=", "id=", "data-sitekey", "hcaptcha.")
        )
    )
    if has_hcaptcha_script or has_hcaptcha_widget:
        return AntiBotResult(
            vendor="hcaptcha",
            kind="captcha",
            evidence=["body:hcaptcha_widget"],
        )

    # -------------------------------------------------------------
    # 10. Generic Bot Protection / Challenge Phrases
    # -------------------------------------------------------------
    generic_phrases = [
        "verify you are human",
        "xác minh bạn là người",
        "kiểm tra trình duyệt",
        "bot protection",
        "enable javascript to continue",
        "vui lòng bật javascript",
    ]
    for phrase in generic_phrases:
        if phrase in body_lower:
            # Avoid false positive on news/educational articles mentioning 'bot protection' casually
            if phrase == "bot protection":
                is_challenge_context = (
                    status in (403, 429, 503)
                    or any(
                        chk in body_lower
                        for chk in (
                            "security check", "ddos", "protected by", "ray id", "verify",
                            "checking", "under bot protection", "active bot protection",
                            "cloudflare", "waf", "challenge", "please wait"
                        )
                    )
                )
                if not is_challenge_context:
                    continue

            kind = "captcha" if ("xác minh" in phrase or "verify" in phrase) else "challenge"
            return AntiBotResult(
                vendor="generic",
                kind=kind,
                evidence=[f"body:phrase:{phrase}"],
            )

    # -------------------------------------------------------------
    # 11. Interstitial rút gọn (Shortener Interstitial)
    # -------------------------------------------------------------
    interstitial_phrases = [
        "click to continue",
        "nhấn để tiếp tục",
        "skip ad",
        "adf.ly",
    ]
    for iphrase in interstitial_phrases:
        if iphrase in body_lower:
            return AntiBotResult(
                vendor="generic",
                kind="interstitial",
                evidence=[f"body:interstitial:{iphrase}"],
            )

    # -------------------------------------------------------------
    # 12. Trang chỉ-JS (JS-only redirect / blank page)
    # Body < 512 bytes with JS redirection or noscript and no visible content
    # -------------------------------------------------------------
    body_stripped = body_text.strip()
    if 0 < len(body_stripped) < 512:
        has_js_redirect = (
            "<noscript>" in body_lower
            or "window.location" in body_lower
            or "location.href" in body_lower
            or "location.replace" in body_lower
        )
        has_empty_meta_refresh = (
            ("http-equiv=\"refresh\"" in body_lower
             or "http-equiv='refresh'" in body_lower
             or "http-equiv=refresh" in body_lower)
            and "url=" not in body_lower
        )
        if has_js_redirect or has_empty_meta_refresh:
            # Strip script and style tags and contents to check if meaningful visible text exists (linear, no .*)
            cleaned_html = re.sub(r"(?i)<script[^>]{0,100}>[^<]{0,500}</script>", "", body_text)
            cleaned_html = re.sub(r"(?i)<style[^>]{0,100}>[^<]{0,500}</style>", "", cleaned_html)
            text_without_tags = re.sub(r"<[^>]{0,200}>", "", cleaned_html)
            text_without_tags = re.sub(r"\s+", "", text_without_tags)
            if len(text_without_tags) < 60:
                return AntiBotResult(
                    vendor="generic",
                    kind="js_only",
                    evidence=["short_body_js_redirect"],
                )

    # -------------------------------------------------------------
    # 13. Generic 403 Short/Empty Block
    # 403 on a site with short or empty body and no specific signs
    # -------------------------------------------------------------
    if status == 403:
        stripped_len = len(body_stripped)
        if stripped_len == 0 or stripped_len < 256:
            text_without_tags = re.sub(r"<[^>]{0,200}>", "", body_text).strip().lower()
            if text_without_tags in (
                "",
                "403 forbidden",
                "forbidden",
                "access denied",
                "403",
                "error 403",
            ) or stripped_len < 100:
                return AntiBotResult(
                    vendor="generic",
                    kind="block",
                    evidence=[f"status:{status}", "short_body_403"],
                )

    return None
