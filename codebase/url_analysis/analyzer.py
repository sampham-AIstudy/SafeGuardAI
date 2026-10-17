from __future__ import annotations

import re
import time
import urllib.parse
from typing import Any

from codebase.url_analysis.blacklist import PhishBlacklist
from codebase.url_analysis.brands import BrandCatalog
from codebase.url_analysis.decode import peel_url
from codebase.url_analysis.extract import extract_candidates
from codebase.url_analysis.models import (
    Candidate,
    ObfuscationStep,
    ParsedUrl,
    UrlAnalysisReport,
    UrlFinding,
    UrlSignal,
)
from codebase.url_analysis.normalize import load_url_lists, normalize_for_urls
from codebase.url_analysis.parse import parse_url

MAX_TEXT_CHARS = 20000


class UrlAnalyzer:
    """
    Main Coordinator and Scoring Engine for URL Deobfuscation & Analysis.
    Never raises an unhandled exception on arbitrary input.
    """

    def __init__(
        self,
        catalog: BrandCatalog | None = None,
        lists: dict[str, Any] | None = None,
        resolver: Any = None,
        blacklist: PhishBlacklist | None = None,
    ):
        self.catalog = catalog or BrandCatalog.load()
        self.lists = lists or load_url_lists()
        self.resolver = resolver
        self.blacklist = blacklist if blacklist is not None else PhishBlacklist.from_dataset()

        # Cache config sets
        self.shorteners = {s.lower().strip(".") for s in self.lists.get("shorteners", [])}
        self.suspicious_tlds = {t.lower().strip(".") for t in self.lists.get("suspicious_tlds", [])}
        self.free_hosting = {h.lower().strip(".") for h in self.lists.get("free_hosting", [])}
        self.valid_tlds = {t.lower().strip(".") for t in self.lists.get("valid_tlds", [])}
        self.redirectors = self.lists.get("redirectors", {})
        self.lure_tokens = [t.lower().strip() for t in self.lists.get("lure_tokens", []) if t.strip()]

        # Free hosting platforms
        self.free_hosting.add("notion.site")

        plat_from_catalog = {
            p.lower().strip(".") for p in getattr(self.catalog, "platform_domains", set())
        }
        if not plat_from_catalog:
            from codebase.url_analysis.blacklist import _get_platform_and_free_hosting
            plat_from_catalog = _get_platform_and_free_hosting()

        self.platform_domains = {
            p.lower().strip(".") for p in self.lists.get("platform_domains", [])
        } | plat_from_catalog

    def _is_official_or_platform(self, host: str, registrable: str) -> bool:
        if not host:
            return False
        h = host.lower().strip(".")
        reg = (registrable or "").lower().strip(".")
        is_off, _ = self.catalog.is_official(h)
        if is_off:
            return True
        for p in self.platform_domains:
            p_clean = p.lower().strip(".")
            # Exclude free hosting domains from protected platform exemption
            if p_clean not in self.free_hosting:
                if h == p_clean or reg == p_clean or h.endswith("." + p_clean):
                    return True
        return False

    def _is_platform_domain(self, host: str, registrable: str) -> bool:
        if not host:
            return False
        h = host.lower().strip(".")
        reg = (registrable or "").lower().strip(".")
        if h in self.platform_domains or reg in self.platform_domains:
            return True
        return any(h.endswith("." + p) for p in self.platform_domains)

    def _is_platform_or_free_hosting(self, host: str, registrable: str) -> bool:
        return self._is_free_hosting(host, registrable) or self._is_platform_domain(host, registrable)

    def _find_lure_tokens(self, host: str, registrable: str) -> list[str]:
        if not host:
            return []
        h = host.lower().strip(".")
        labels = h.split(".")
        multi_suffixes = {s.lower() for s in self.lists.get("multi_level_suffixes", [])}
        if len(labels) >= 3 and f"{labels[-2]}.{labels[-1]}".lower() in multi_suffixes:
            domain_labels = labels[:-2]
        elif len(labels) >= 2 and labels[-1] in self.valid_tlds:
            domain_labels = labels[:-1]
        else:
            domain_labels = labels

        matched: list[str] = []
        for token in self.lure_tokens:
            tok = token.lower().strip()
            if not tok:
                continue
            is_match = False
            for dl in domain_labels:
                sub_parts = [s for s in dl.split("-") if s]
                no_hyphen = dl.replace("-", "")
                if len(tok) >= 5:
                    if tok in dl or tok in no_hyphen or any(tok in s for s in sub_parts):
                        is_match = True
                        break
                else:
                    if tok == dl or tok == no_hyphen or any(tok == s for s in sub_parts):
                        is_match = True
                        break
            if is_match:
                matched.append(tok)
        return matched

    def _find_lure_tokens_in_path(self, path: str, query: str = "") -> list[str]:
        raw_text = f"{path or ''} {query or ''}"
        if not raw_text.strip():
            return []

        # Safe decode percent-encoding
        try:
            unquoted = urllib.parse.unquote(raw_text).lower()
        except Exception:
            unquoted = raw_text.lower()

        # Split path and query into segments by slash and query separators
        segments = [s for s in re.split(r"[/\\?&=]+", unquoted) if s]

        matched: list[str] = []
        for token in self.lure_tokens:
            tok = token.lower().strip()
            if not tok:
                continue

            is_match = False
            for seg in segments:
                sub_parts = [p for p in re.split(r"[-_.]+", seg) if p]
                no_sep = re.sub(r"[-_.]+", "", seg)

                if len(tok) >= 5:
                    if tok in seg or tok in no_sep or any(tok in p for p in sub_parts):
                        is_match = True
                        break
                else:
                    if tok == seg or tok == no_sep or any(tok == p for p in sub_parts):
                        is_match = True
                        break

            if is_match:
                matched.append(tok)

        return matched

    def _is_shortener(self, host: str) -> bool:
        if not host:
            return False
        h = host.lower().strip(".")
        return h in self.shorteners or any(h.endswith("." + s) for s in self.shorteners)

    def _is_suspicious_tld(self, host: str, registrable: str) -> bool:
        target = registrable or host
        if not target or "." not in target:
            return False
        tld = target.split(".")[-1].lower()
        return tld in self.suspicious_tlds

    def _is_free_hosting(self, host: str, registrable: str) -> bool:
        h = (host or "").lower().strip(".")
        reg = (registrable or "").lower().strip(".")
        if h in self.free_hosting or reg in self.free_hosting:
            return True
        return any(h.endswith("." + fh) for fh in self.free_hosting)

    def _is_trusted_redirector(self, host: str, path: str) -> bool:
        h = (host or "").lower().strip(".")
        p = (path or "").strip("/")
        for redir_pattern in self.redirectors.keys():
            if "/" in redir_pattern:
                r_host, r_path = redir_pattern.split("/", 1)
                if (h == r_host or h.endswith("." + r_host)) and p.startswith(r_path):
                    return True
            else:
                if h == redir_pattern or h.endswith("." + redir_pattern):
                    return True
        return False

    def analyze_text(
        self,
        text: str,
        extra_urls: list[tuple[str, str]] | None = None,
        allow_network: bool = False,
        deadline_s: float = 6.0,
    ) -> UrlAnalysisReport:
        """
        Analyze all URLs inside a given text string.
        Guarantees:
          - Never raises exceptions.
          - Execution time < 150ms on 20k chars / 20 URLs.
        """
        start_time = time.perf_counter()

        try:
            if not isinstance(text, str):
                text = str(text or "")

            text_truncated = len(text) > MAX_TEXT_CHARS
            clipped_text = text[:MAX_TEXT_CHARS] if text_truncated else text

            # 1. Normalize
            norm_text, norm_steps, norm_stats = normalize_for_urls(clipped_text)

            # 2. Extract
            candidates = extract_candidates(norm_text, extra_urls=extra_urls, stats=norm_stats)
            is_truncated = text_truncated or getattr(candidates, "truncated", False)

            # 3. Analyze each candidate
            findings: list[UrlFinding] = []
            for cand in candidates:
                # Associate initial normalization steps if applicable
                f = self.analyze_url(
                    cand.raw,
                    source=cand.source,
                    display_text=cand.display_text,
                    allow_network=allow_network,
                    depth=0,
                    obfuscation_steps=norm_steps,
                )
                findings.append(f)

            # 4. Aggregates
            max_url_risk = max((f.url_risk_score for f in findings), default=0)

            # has_obfuscation: True if any finding has obfuscation steps or obfuscation signals
            obf_codes = {
                "ZERO_WIDTH", "FULLWIDTH_OR_ODD_DOT", "DEFANGED", "ENCODED_HOST",
                "DOUBLE_ENCODING", "BASE64_URL", "HEX_URL", "IP_OBFUSCATED",
                "BACKSLASH_CONFUSION", "USERINFO_PRESENT",
            }
            has_obfuscation = any(
                len(f.obfuscation_chain) > 0 or any(s.code in obf_codes for s in f.signals)
                for f in findings
            )

            # has_only_official_urls: True if all findings (and children) are official
            def _all_official(flist: list[UrlFinding]) -> bool:
                for f in flist:
                    if not f.is_official:
                        return False
                    if f.children and not _all_official(f.children):
                        return False
                return True

            has_only_official = _all_official(findings) if findings else False

            # Critical codes
            crit_set: set[str] = set()
            for f in findings:
                for s in f.signals:
                    if s.severity == "critical":
                        crit_set.add(s.code)
                for ch in f.children:
                    for s in ch.signals:
                        if s.severity == "critical":
                            crit_set.add(s.code)
            critical_codes = sorted(list(crit_set))

            # Summary messages in Vietnamese
            summary_vi: list[str] = []
            if max_url_risk >= 70:
                summary_vi.append("Phát hiện liên kết có mức độ nguy hiểm cao, tiềm ẩn nguy cơ lừa đảo hoặc mã độc.")
            elif max_url_risk >= 40:
                summary_vi.append("Phát hiện liên kết đáng ngờ, cần thận trọng trước khi truy cập.")
            elif has_only_official:
                summary_vi.append("Tất cả các liên kết đều thuộc tên miền chính thức đã được xác thực.")
            elif findings:
                summary_vi.append("Không phát hiện dấu hiệu lừa đảo nguy hiểm trên các liên kết được phân tích.")
            else:
                summary_vi.append("Không tìm thấy liên kết nào trong nội dung.")

            for f in findings:
                for s in f.signals:
                    if s.severity in ("critical", "high") and s.message_vi not in summary_vi:
                        summary_vi.append(s.message_vi)

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            return UrlAnalysisReport(
                findings=findings,
                max_url_risk=max_url_risk,
                has_obfuscation=has_obfuscation,
                has_only_official_urls=has_only_official,
                critical_codes=critical_codes,
                summary_vi=summary_vi,
                truncated=is_truncated,
                elapsed_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return UrlAnalysisReport(
                findings=[],
                max_url_risk=0,
                has_obfuscation=False,
                has_only_official_urls=False,
                critical_codes=[],
                summary_vi=[f"Lỗi khi phân tích liên kết: {e}"],
                truncated=False,
                elapsed_ms=elapsed_ms,
            )

    def analyze_url(
        self,
        raw: str,
        *,
        source: str = "text",
        display_text: str | None = None,
        allow_network: bool = False,
        depth: int = 0,
        seen_urls: set[str] | None = None,
        obfuscation_steps: list[ObfuscationStep] | None = None,
    ) -> UrlFinding:
        """
        Analyze a single URL candidate recursively.
        """
        if seen_urls is None:
            seen_urls = set()

        if raw in seen_urls or depth > 2:
            p = parse_url(raw)
            return UrlFinding(
                raw=raw,
                normalized=raw,
                final_url=raw,
                display_host=p.display_host,
                effective_host=p.effective_host,
                effective_host_unicode=p.effective_host_unicode,
                registrable_domain=p.registrable_domain,
                is_official=False,
                brand_match=None,
                source=source,
                verdict="unknown",
            )
        seen_urls.add(raw)

        # 1. Parse URL safely
        parsed = parse_url(raw)
        effective_host = parsed.effective_host
        display_host = parsed.display_host
        registrable = parsed.registrable_domain

        # 2. Peel embedded & redirect parameters
        peel_res = peel_url(parsed, max_depth=4)

        # 3. Check official brand catalog
        is_off, off_brand = self.catalog.is_official(effective_host)

        # 4. Check brand impersonation match
        b_match = self.catalog.brand_match(effective_host, registrable, parsed.path, parsed.query)

        # 5. Check blacklist
        bl_res = self.blacklist.lookup(parsed)

        # 6. Build obfuscation chain
        obf_steps: list[ObfuscationStep] = list(obfuscation_steps or []) + list(peel_res.steps)
        if "BACKSLASH_CONFUSION" in parsed.flags:
            obf_steps.append(
                ObfuscationStep(
                    technique="backslash",
                    detail_vi="Sử dụng dấu gạch chéo ngược (\\) thay cho (/) trong URL",
                    before=raw[:200],
                    after=effective_host[:200],
                )
            )
        if "USERINFO_PRESENT" in parsed.flags:
            obf_steps.append(
                ObfuscationStep(
                    technique="userinfo",
                    detail_vi=f"Phần trước dấu @ ({parsed.userinfo}) là userinfo đánh lừa",
                    before=parsed.userinfo[:200],
                    after=effective_host[:200],
                )
            )

        # 7. Build Signals
        signals: list[UrlSignal] = []
        seen_codes: set[str] = set()

        def add_sig(code: str, severity: str, weight: int, message_vi: str, evidence: str):
            if code not in seen_codes:
                seen_codes.add(code)
                signals.append(
                    UrlSignal(
                        code=code,
                        severity=severity,
                        weight=weight,
                        message_vi=message_vi,
                        evidence=evidence,
                    )
                )

        # Signal: USERINFO
        if "USERINFO_PRESENT" in parsed.flags:
            is_decoy = False
            if display_host and display_host != effective_host:
                cand_off, cand_brand = self.catalog.is_official(display_host)
                cand_match = self.catalog.brand_match(display_host)
                if (
                    cand_off
                    or cand_match
                    or display_host.endswith(".gov.vn")
                    or any(k in display_host for _, k, _ in self.catalog.brand_keywords if len(k) >= 4)
                ):
                    is_decoy = True
                    b_name = (
                        cand_brand["display_name"]
                        if cand_brand
                        else (cand_match["display_name"] if cand_match else display_host)
                    )
                    add_sig(
                        "USERINFO_BRAND_DECOY",
                        "critical",
                        60,
                        f"Phần trước dấu @ ({parsed.userinfo}) chỉ là tên đăng nhập giả mạo thương hiệu {b_name}; trình duyệt thực sự mở {effective_host}.",
                        f"userinfo={parsed.userinfo}, effective_host={effective_host}",
                    )
            if not is_decoy:
                add_sig(
                    "USERINFO_PRESENT",
                    "medium",
                    25,
                    f"URL chứa thành phần đăng nhập userinfo ({parsed.userinfo}) phía trước tên miền thực sự.",
                    f"userinfo={parsed.userinfo}",
                )

        # Signal: BRAND IMPERSONATION
        if b_match:
            tech = b_match.get("technique")
            b_name = b_match.get("display_name", "")
            off_dom = b_match.get("official_domain", "")
            if tech == "homoglyph":
                add_sig(
                    "HOMOGLYPH_BRAND",
                    "critical",
                    60,
                    f"Tên miền sử dụng ký tự đồng dạng (homoglyph) để giả mạo thương hiệu {b_name}.",
                    f"host={effective_host}, brand={b_name}",
                )
            elif tech == "typosquat":
                add_sig(
                    "TYPOSQUAT_BRAND",
                    "high",
                    50,
                    f"Tên miền cố tình gõ sai chính tả (typosquat) để mạo danh thương hiệu {b_name}.",
                    f"host={effective_host}, dist={b_match.get('distance', 1)}",
                )
            elif tech == "tld_swap":
                add_sig(
                    "BRAND_TLD_SWAP",
                    "high",
                    45,
                    f"Tên miền đổi đuôi TLD khác với tên miền chính thức của {b_name} ({off_dom}).",
                    f"host={effective_host}, official={off_dom}",
                )
            elif tech in ("combosquat", "subdomain_brand"):
                add_sig(
                    "COMBOSQUAT_BRAND",
                    "high",
                    45,
                    f"Tên miền chèn từ khóa/thương hiệu {b_name} nhằm đánh lừa người dùng.",
                    f"host={effective_host}, technique={tech}",
                )
            elif tech == "path_brand":
                add_sig(
                    "BRAND_IN_PATH",
                    "low",
                    15,
                    f"Đường dẫn URL chứa tên thương hiệu {b_name} trên máy chủ không chính thức.",
                    f"path={parsed.path}",
                )

        # Signal: BLACKLIST
        if bl_res.get("hit"):
            level = bl_res.get("level", "domain")
            # Official domains can never be blacklisted by host or registrable
            if is_off and level != "path":
                pass
            else:
                add_sig(
                    "BLACKLIST_HIT",
                    "critical",
                    60,
                    f"Tên miền nằm trong danh sách đen PhishVN ({level} match).",
                    f"host={effective_host}, level={level}",
                )

        # Signal: BACKSLASH CONFUSION
        if "BACKSLASH_CONFUSION" in parsed.flags:
            add_sig(
                "BACKSLASH_CONFUSION",
                "high",
                50,
                "Sử dụng dấu gạch chéo ngược (\\) để đánh lừa bộ phân tích URL.",
                f"raw={raw}",
            )

        # Signal: APK DOWNLOAD
        p_low = (parsed.path or "").lower()
        h_low = effective_host.lower()
        if (
            p_low.endswith((".apk", ".xapk", ".apks"))
            or ".apk" in p_low
            or ".apk?" in raw.lower()
            or h_low.endswith(".apk")
        ):
            add_sig(
                "APK_DOWNLOAD",
                "critical",
                60,
                "Đường dẫn trực tiếp tải về tệp ứng dụng Android (.apk) tiềm ẩn mã độc.",
                f"url={raw}",
            )

        # Signal: DATA OR JS URI
        if "DATA_OR_JS_URI" in parsed.flags or parsed.scheme in ("data", "javascript", "vbscript"):
            add_sig(
                "DATA_OR_JS_URI",
                "critical",
                60,
                "URI nguy hiểm dạng data: hoặc javascript: có thể tự động thực thi mã lệnh.",
                f"scheme={parsed.scheme}",
            )

        # Signal: ANCHOR MISMATCH
        if display_text and source in ("anchor", "markdown"):
            d_text = display_text.strip()
            if "." in d_text and any(c.isalpha() for c in d_text) and not any(c in d_text for c in " \t\r\n"):
                d_parsed = parse_url(d_text if "://" in d_text else f"http://{d_text}")
                d_host = d_parsed.effective_host
                if d_host and d_host != effective_host:
                    add_sig(
                        "ANCHOR_MISMATCH",
                        "high",
                        45,
                        f"Văn bản hiển thị là '{d_text}' nhưng liên kết thực sự mở '{effective_host}'.",
                        f"display_host={d_host}, effective_host={effective_host}",
                    )

        # Signal: IP HOST / IP OBFUSCATED
        if "IP_OBFUSCATED" in parsed.flags:
            add_sig(
                "IP_OBFUSCATED",
                "high",
                45,
                f"Địa chỉ IP máy chủ bị làm mờ/lạ mắt (dạng hex/octal/decimal): {parsed.ip}.",
                f"ip={parsed.ip}",
            )
        elif "IP_HOST" in parsed.flags or parsed.ip:
            add_sig(
                "IP_HOST",
                "medium",
                30,
                f"Sử dụng trực tiếp địa chỉ IP ({parsed.ip}) thay vì tên miền thương hiệu.",
                f"ip={parsed.ip}",
            )

        # Signal: MIXED SCRIPT
        if "MIXED_SCRIPT" in parsed.flags:
            add_sig(
                "MIXED_SCRIPT",
                "high",
                40,
                "Tên miền pha trộn nhiều bảng chữ cái khác nhau (Latin, Cyrillic, Greek).",
                f"host={parsed.effective_host_unicode}",
            )

        # Signal: ENCODED HOST
        if "ENCODED_HOST" in parsed.flags:
            add_sig(
                "ENCODED_HOST",
                "high",
                35,
                "Tên miền sử dụng ký tự mã hóa phần trăm (%xx) để ẩn giấu.",
                f"raw_host={raw}",
            )

        # Signal: DOUBLE ENCODING
        if "DOUBLE_ENCODING" in peel_res.flags or "DOUBLE_ENCODING" in parsed.flags:
            add_sig(
                "DOUBLE_ENCODING",
                "medium",
                20,
                "URL bị mã hóa kép (%25) để né tránh các bộ lọc an ninh.",
                "double_percent_encoding",
            )

        # Signal: BASE64 / HEX
        if "BASE64_URL" in peel_res.flags:
            add_sig(
                "BASE64_URL",
                "medium",
                25,
                "URL chứa tham số mã hóa Base64 ẩn giấu liên kết thực sự.",
                "base64_param",
            )
        if "HEX_URL" in peel_res.flags:
            add_sig(
                "HEX_URL",
                "medium",
                25,
                "URL chứa tham số mã hóa Hexadecimal ẩn giấu liên kết thực sự.",
                "hex_param",
            )

        # Signal: ZERO WIDTH
        if any(s.technique == "zero_width" for s in obf_steps):
            add_sig(
                "ZERO_WIDTH",
                "medium",
                30,
                "Phát hiện ký tự ẩn / độ rộng bằng 0 (zero-width) trong liên kết.",
                "zero_width",
            )

        # Signal: FULLWIDTH / ODD DOT
        if any(s.technique in ("fullwidth", "odd_dot") for s in obf_steps):
            add_sig(
                "FULLWIDTH_OR_ODD_DOT",
                "medium",
                20,
                "Liên kết sử dụng ký tự fullwidth hoặc dấu chấm lạ để đánh lừa.",
                "fullwidth_or_odd_dot",
            )

        # Signal: SHORTENER
        if self._is_shortener(effective_host):
            add_sig(
                "SHORTENER",
                "medium",
                20,
                f"Liên kết sử dụng dịch vụ rút gọn link ({effective_host}) che giấu đích đến.",
                f"host={effective_host}",
            )

        # Signal: SUSPICIOUS TLD
        if self._is_suspicious_tld(effective_host, registrable):
            add_sig(
                "SUSPICIOUS_TLD",
                "low",
                15,
                f"Tên miền sử dụng đuôi lạ/tiềm ẩn rủi ro cao (.{effective_host.split('.')[-1]}).",
                f"host={effective_host}",
            )

        # Signal: FREE HOSTING
        if self._is_free_hosting(effective_host, registrable):
            add_sig(
                "FREE_HOSTING",
                "low",
                15,
                f"Liên kết đặt trên nền tảng hosting/chia sẻ miễn phí ({effective_host}).",
                f"host={effective_host}",
            )

        # Signal: LURE KEYWORD DOMAIN
        lure_matches = self._find_lure_tokens(effective_host, registrable)
        if lure_matches and not self._is_official_or_platform(effective_host, registrable):
            has_suspicious_tld = self._is_suspicious_tld(effective_host, registrable)
            has_free_hosting = self._is_free_hosting(effective_host, registrable)
            has_brand_match = bool(b_match)
            reg_label = (registrable or effective_host).split(".")[0]
            has_hyphens = reg_label.count("-") >= 2

            if has_suspicious_tld or has_free_hosting or has_brand_match or has_hyphens:
                matched_str = ", ".join(sorted(list(set(lure_matches))))
                add_sig(
                    "LURE_KEYWORD_DOMAIN",
                    "medium",
                    25,
                    f"Tên miền chứa từ khóa mồi nhử lừa đảo '{matched_str}' kết hợp với các yếu tố bất thường.",
                    f"host={effective_host}, tokens={matched_str}",
                )

        # Signal: LURE KEYWORD PATH
        if not is_off and self._is_platform_or_free_hosting(effective_host, registrable):
            lure_path_matches = self._find_lure_tokens_in_path(parsed.path, parsed.query)
            if lure_path_matches:
                matched_path_str = ", ".join(sorted(list(set(lure_path_matches))))
                add_sig(
                    "LURE_KEYWORD_PATH",
                    "medium",
                    20,
                    f"Đường dẫn URL chứa từ khóa mồi nhử lừa đảo '{matched_path_str}' trên nền tảng người dùng/hosting miễn phí.",
                    f"path={parsed.path}, tokens={matched_path_str}",
                )

        # Signal: INVALID TLD
        is_invalid_tld = (
            "INVALID_TLD" in parsed.flags
            or (
                bool(effective_host)
                and not parsed.ip
                and "." in effective_host
                and bool(self.valid_tlds)
                and effective_host.split(".")[-1].lower() not in self.valid_tlds
                and not effective_host.split(".")[-1].isdigit()
            )
        )
        if is_invalid_tld:
            add_sig(
                "INVALID_TLD",
                "medium",
                20,
                "Tên miền có đuôi TLD không hợp lệ theo tiêu chuẩn quốc tế.",
                f"host={effective_host}",
            )

        # Signal: INVALID IDN
        if "INVALID_IDN" in parsed.flags:
            add_sig(
                "INVALID_IDN",
                "medium",
                30,
                "Tên miền quốc tế hóa (IDN) không hợp lệ hoặc chứa lỗi mã hóa.",
                f"host={effective_host}",
            )

        # Signal: PUNYCODE HOST
        if "PUNYCODE_HOST" in parsed.flags or effective_host.startswith("xn--"):
            add_sig(
                "PUNYCODE_HOST",
                "low",
                15,
                f"Tên miền sử dụng mã Punycode ({effective_host}).",
                f"host={effective_host}",
            )

        # Signal: NON STANDARD PORT
        if "NON_STANDARD_PORT" in parsed.flags:
            add_sig(
                "NON_STANDARD_PORT",
                "low",
                10,
                f"Liên kết sử dụng cổng mạng không tiêu chuẩn (port {parsed.port}).",
                f"port={parsed.port}",
            )

        # Signal: DEEP SUBDOMAIN
        if "DEEP_SUBDOMAIN" in parsed.flags:
            add_sig(
                "DEEP_SUBDOMAIN",
                "low",
                10,
                "Tên miền có quá nhiều cấp miền con (subdomain sâu >= 4 nhãn).",
                f"host={effective_host}",
            )

        # Signal: LONG URL
        if "LONG_URL" in parsed.flags:
            add_sig(
                "LONG_URL",
                "low",
                10,
                "URL có độ dài bất thường (> 2048 ký tự).",
                f"len={len(raw)}",
            )

        # Signal: DEFANGED
        if any(s.technique == "defanged" for s in obf_steps):
            add_sig(
                "DEFANGED",
                "info",
                5,
                "Liên kết đã được gỡ defang về dạng URL chuẩn.",
                "defanged",
            )

        # Signal: HTTP PLAIN
        if parsed.scheme == "http" and not parsed.ip:
            add_sig(
                "HTTP_PLAIN",
                "info",
                5,
                "Liên kết sử dụng giao thức HTTP không mã hóa.",
                "http",
            )

        # Signal: OFFICIAL DOMAIN
        if is_off:
            brand_name = off_brand["display_name"] if off_brand else "Đơn vị chính phủ"
            add_sig(
                "OFFICIAL_DOMAIN",
                "info",
                0,
                f"Tên miền chính thức đã được xác thực của {brand_name} ({effective_host}).",
                f"host={effective_host}",
            )

        # 8. Recursive analysis of inner/redirected URLs
        children: list[UrlFinding] = []
        if peel_res.inner and depth < 2:
            for inner_cand in peel_res.inner:
                ch = self.analyze_url(
                    inner_cand.raw,
                    source=inner_cand.source,
                    display_text=inner_cand.display_text,
                    allow_network=allow_network,
                    depth=depth + 1,
                    seen_urls=seen_urls,
                )
                children.append(ch)

        # Check OPEN_REDIRECT_TRUSTED
        if self._is_trusted_redirector(effective_host, parsed.path) and children:
            if any(not ch.is_official for ch in children):
                add_sig(
                    "OPEN_REDIRECT_TRUSTED",
                    "high",
                    40,
                    f"Domain uy tín ({effective_host}) bị lợi dụng làm bàn đạp chuyển hướng (open redirect) tới trang không chính thức.",
                    f"redirector={effective_host}, target={children[0].effective_host}",
                )
        elif children and not any(s.code == "OPEN_REDIRECT_TRUSTED" for s in signals):
            add_sig(
                "EMBEDDED_URL",
                "low",
                15,
                "URL chứa một liên kết khác được nhúng bên trong.",
                f"target={children[0].raw}",
            )

        # 9. Compute Risk Score & Verdict
        self_risk = min(99, sum(s.weight for s in signals))
        max_child_risk = max((ch.url_risk_score for ch in children), default=0)
        final_risk = max(self_risk, max_child_risk)

        if is_off:
            has_medium_plus = any(s.severity in ("medium", "high", "critical") for s in signals)
            if not has_medium_plus and max_child_risk == 0:
                final_risk = 0
                verdict = "official"
            else:
                if final_risk >= 70:
                    verdict = "dangerous"
                elif final_risk >= 40:
                    verdict = "suspicious"
                elif final_risk >= 1:
                    verdict = "low"
                else:
                    verdict = "official"
        else:
            if final_risk >= 70:
                verdict = "dangerous"
            elif final_risk >= 40:
                verdict = "suspicious"
            elif final_risk >= 1:
                verdict = "low"
            else:
                verdict = "benign"

        return UrlFinding(
            raw=raw,
            normalized=raw,
            final_url=children[-1].final_url if (children and self._is_trusted_redirector(effective_host, parsed.path)) else raw,
            display_host=display_host,
            effective_host=effective_host,
            effective_host_unicode=parsed.effective_host_unicode,
            registrable_domain=registrable,
            is_official=is_off,
            brand_match=b_match,
            source=source,
            obfuscation_chain=obf_steps,
            redirect_chain=[],
            signals=signals,
            children=children,
            url_risk_score=final_risk,
            verdict=verdict,
            network_used=False,
            errors=[],
        )
