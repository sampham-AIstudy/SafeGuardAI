from __future__ import annotations

import re
import threading
import time
import urllib.parse
from typing import Any

from codebase.url_analysis.blacklist import PhishBlacklist
from codebase.url_analysis.brands import BrandCatalog
from codebase.url_analysis.decode import peel_url
from codebase.url_analysis.extract import extract_candidates
from codebase.url_analysis.models import (
    ObfuscationStep,
    UrlAnalysisReport,
    UrlFinding,
    UrlSignal,
)
from codebase.url_analysis.normalize import load_url_lists, normalize_for_urls
from codebase.url_analysis.parse import parse_url

MAX_TEXT_CHARS = 20000


class AnalysisDict(dict):
    """Dictionary supporting attribute access for report structures."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'AnalysisDict' has no attribute '{name}'")


def _wrap_report_dict(val: Any) -> Any:
    """Recursively wrap objects and dicts into AnalysisDict for attribute access."""
    if hasattr(val, "to_dict") and callable(val.to_dict):
        return AnalysisDict(_wrap_report_dict(val.to_dict()))
    elif isinstance(val, dict):
        return AnalysisDict({k: _wrap_report_dict(v) for k, v in val.items()})
    elif isinstance(val, list):
        return [_wrap_report_dict(item) for item in val]
    return val


def _clean_text_for_url_analysis(text: str) -> str:
    """Pre-clean text for URL analysis (e.g. separating standalone time strings)."""
    if not isinstance(text, str):
        text = str(text or "")
    return re.sub(
        r'(?<![0-9a-zA-Z/])(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?![0-9a-zA-Z/]|(?:\.[a-zA-Z]))',
        ' ',
        text,
    )

_shared_analyzer_lock = threading.Lock()
_shared_analyzer_instance: UrlAnalyzer | None = None


def get_shared_url_analyzer(force_refresh: bool = False) -> UrlAnalyzer:
    """
    Thread-safe getter for singleton UrlAnalyzer instance with full PhishBlacklist
    (including platform exclusions, official domains, and conflicted host handling).
    """
    global _shared_analyzer_instance
    if _shared_analyzer_instance is None or force_refresh:
        with _shared_analyzer_lock:
            if _shared_analyzer_instance is None or force_refresh:
                try:
                    from codebase.knowledge_base.dataset_loader import DatasetLoader
                    loader = DatasetLoader()
                    phish_data = loader.load_phish_vn_datasets()
                    blacklist = PhishBlacklist.from_dataset(phish_data)
                    _shared_analyzer_instance = UrlAnalyzer(blacklist=blacklist)
                    _shared_analyzer_instance._source_data_id = id(phish_data)
                    _shared_analyzer_instance._source_domains_hash = hash(frozenset(phish_data.get("phishing_domains", set())))
                except Exception:
                    blacklist = PhishBlacklist.from_dataset()
                    _shared_analyzer_instance = UrlAnalyzer(blacklist=blacklist)
                    _shared_analyzer_instance._source_data_id = None
                    _shared_analyzer_instance._source_domains_hash = None
    return _shared_analyzer_instance


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
        passive_intel: Any = None,
    ):
        self.catalog = catalog or BrandCatalog.load()
        self.lists = lists or load_url_lists()
        self.resolver = resolver
        self._default_resolver: Any = None
        self.blacklist = blacklist if blacklist is not None else PhishBlacklist.from_dataset()
        self.passive_intel = passive_intel
        self._default_passive_intel: Any = None

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
        if hasattr(self.catalog, "is_related"):
            is_rel, _ = self.catalog.is_related(h)
            if is_rel:
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

    def _is_network_permitted(self, allow_network: bool) -> bool:
        if not allow_network:
            return False
        try:
            from codebase.config import get_settings
            settings = get_settings()
            return bool(getattr(settings, "network_enabled", False)) and not bool(getattr(settings, "offline", False))
        except Exception:
            return False

    def _get_resolver(self) -> Any:
        if self.resolver is not None:
            return self.resolver
        if self._default_resolver is None:
            from codebase.url_analysis.resolver import SafeRedirectResolver
            self._default_resolver = SafeRedirectResolver(lists=self.lists)
        return self._default_resolver

    def _get_passive_intel(self) -> Any:
        if self.passive_intel is not None:
            return self.passive_intel
        if self._default_passive_intel is None:
            from codebase.url_analysis.passive import PassiveIntel
            resolver = self._get_resolver()
            self._default_passive_intel = PassiveIntel(
                fetch=resolver.fetch if hasattr(resolver, "fetch") else None
            )
        return self._default_passive_intel

    def _is_dest_official(self, url_or_host: str) -> bool:
        if not url_or_host:
            return False
        h = url_or_host
        if "://" in h or "/" in h:
            try:
                p = parse_url(h)
                h = p.effective_host or p.display_host or h
            except Exception:
                pass
        h = (h or "").lower().strip(".")
        is_off, _ = self.catalog.is_official(h)
        return bool(is_off)

    def _resolve_finding(
        self,
        finding: UrlFinding,
        resolver: Any,
        deadline_s: float,
        depth: int = 0,
        recorder: Any = None,
    ) -> None:
        finding.network_used = True
        target_url = finding.final_url or finding.raw
        try:
            try:
                chain = resolver.resolve(target_url, deadline_s=deadline_s, recorder=recorder)
            except TypeError:
                chain = resolver.resolve(target_url)
        except Exception as e:
            finding.errors.append(f"resolver_error:{type(e).__name__}")
            return

        if not chain:
            return

        if hasattr(chain, "hops") and chain.hops:
            finding.redirect_chain = [
                h.to_dict() if hasattr(h, "to_dict") else dict(h) for h in chain.hops
            ]
            if getattr(chain, "error", None) and finding.redirect_chain:
                finding.redirect_chain[-1]["error"] = chain.error

        # (b) chain.blocked_reason:
        # NETWORK_BLOCKED_PRIVATE CHỈ khi IP literal / URL trực tiếp trỏ tới địa chỉ riêng!
        p_target = parse_url(target_url)

        def _is_private_ip(ip_val: str | None) -> bool:
            if not ip_val:
                return False
            ip_val = ip_val.strip("[]")
            if (
                ip_val.startswith(("10.", "127.", "192.168.", "169.254.", "0."))
                or ip_val == "::1"
            ):
                return True
            if ip_val.startswith("172."):
                parts = ip_val.split(".")
                if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
                    return True
            return False

        is_direct_private = _is_private_ip(p_target.ip)
        if not is_direct_private and getattr(chain, "hops", None):
            for h in chain.hops:
                h_loc = getattr(h, "location", None) or (h.get("location") if isinstance(h, dict) else None)
                if h_loc:
                    p_loc = parse_url(h_loc)
                    if _is_private_ip(p_loc.ip):
                        is_direct_private = True
                        break
                h_u = getattr(h, "url", None) or (h.get("url") if isinstance(h, dict) else None)
                if h_u:
                    p_hu = parse_url(h_u)
                    if _is_private_ip(p_hu.ip):
                        is_direct_private = True
                        break

        if is_direct_private:
            if not any(s.code == "NETWORK_BLOCKED_PRIVATE" for s in finding.signals):
                finding.signals.append(
                    UrlSignal(
                        code="NETWORK_BLOCKED_PRIVATE",
                        severity="high",
                        weight=40,
                        message_vi="Đường link dẫn tới địa chỉ mạng nội bộ.",
                        evidence="direct_private_ip",
                    )
                )
        elif getattr(chain, "blocked_reason", None) and chain.blocked_reason != "not_a_shortener":
            # Tên nội bộ vs DNS lỗi: không lộ oracle private_destination ra ngoài
            if not any(s.code in ("NETWORK_BLOCKED_PRIVATE", "NETWORK_UNREACHABLE") for s in finding.signals):
                finding.signals.append(
                    UrlSignal(
                        code="NETWORK_UNREACHABLE",
                        severity="low",
                        weight=0,
                        message_vi="Không thể kết nối hoặc phân giải đích đến của liên kết.",
                        evidence="unreachable",
                    )
                )

        # (a) nếu final_url khác:
        final_dest = getattr(chain, "final_url", None)
        if final_dest and final_dest.strip() != target_url.strip():
            final_clean = final_dest.strip()
            finding.final_url = final_clean

            if not any(s.code == "SHORTENER_RESOLVED" for s in finding.signals):
                finding.signals.append(
                    UrlSignal(
                        code="SHORTENER_RESOLVED",
                        severity="low",
                        weight=10,
                        message_vi="Liên kết rút gọn đã được giải mã tới đích đến thực tế.",
                        evidence=f"final_url={final_clean}",
                    )
                )

            num_hops = len(getattr(chain, "hops", []))
            if num_hops > 2 and not any(s.code == "REDIRECT_CHAIN" for s in finding.signals):
                finding.signals.append(
                    UrlSignal(
                        code="REDIRECT_CHAIN",
                        severity="low",
                        weight=10,
                        message_vi=f"Chuỗi chuyển hướng nhiều bước ({num_hops} bước) tiềm ẩn rủi ro che giấu đích đến.",
                        evidence=f"hops_count={num_hops}",
                    )
                )

            # Recursive analysis of final_url (độ sâu <= 2)
            if depth < 2:
                child = self.analyze_url(
                    final_clean,
                    source="redirect",
                    allow_network=False,
                    depth=depth + 1,
                )
                finding.children.append(child)
                if child.final_url:
                    finding.final_url = child.final_url
                if child.is_official:
                    # Brand in shortener path was a legitimate route to official domain
                    finding.signals = [
                        s for s in finding.signals if s.code != "BRAND_IN_PATH"
                    ]

            # B1: Phân tích cả host của TỪNG hop trung gian (tối đa 5) như finding con
            if depth < 2 and hasattr(chain, "hops") and chain.hops:
                seen_hop_hosts = {
                    (parse_url(target_url).effective_host or "").lower(),
                    (parse_url(final_clean).effective_host or "").lower(),
                }
                for hop in chain.hops[:5]:
                    hop_url = getattr(hop, "url", None) if not isinstance(hop, dict) else hop.get("url")
                    if not hop_url:
                        continue
                    h_parsed = parse_url(hop_url)
                    h_host = (h_parsed.effective_host or "").lower()
                    if not h_host or h_host in seen_hop_hosts:
                        continue
                    seen_hop_hosts.add(h_host)
                    hop_child = self.analyze_url(
                        hop_url,
                        source="redirect_hop",
                        allow_network=False,
                        depth=depth + 1,
                    )
                    finding.children.append(hop_child)

        # (c) Đích official => không cloaking và ANTIBOT không cộng điểm cha
        is_dest_official = (
            finding.is_official
            or any(getattr(ch, "is_official", False) for ch in finding.children)
            or (bool(finding.final_url) and self._is_dest_official(finding.final_url))
        )

        # chain.antibot có => ANTIBOT_CHALLENGE (weight 10, low, message_vi nêu vendor)
        has_antibot = bool(getattr(chain, "antibot", None))
        if has_antibot:
            vendor_name = chain.antibot.get("vendor", "hệ thống chống bot")
            if not any(s.code == "ANTIBOT_CHALLENGE" for s in finding.signals):
                antibot_weight = 0 if is_dest_official else 10
                finding.signals.append(
                    UrlSignal(
                        code="ANTIBOT_CHALLENGE",
                        severity="low",
                        weight=antibot_weight,
                        message_vi=f"Trang web kích hoạt cơ chế chống bot / kiểm tra người dùng ({vendor_name}).",
                        evidence=f"vendor={vendor_name}, kind={chain.antibot.get('kind', '')}",
                    )
                )

        # (d) CLOAKING_SUSPECTED (S5a):
        if has_antibot and not is_dest_official:
            is_shortener = (
                self._is_shortener(finding.effective_host)
                or any(s.code in ("SHORTENER", "SHORTENER_RESOLVED") for s in finding.signals)
            )
            # Yếu tố phụ chỉ từ tín hiệu của ĐÍCH / domain đích, KHÔNG tính chính shortener
            target_candidates = list(finding.children) if is_shortener else ([finding] + list(finding.children))

            has_brand = any(
                bool(getattr(c, "brand_match", None))
                or any("BRAND" in s.code for s in getattr(c, "signals", []))
                for c in target_candidates
            )
            has_typosquat = any(
                any(s.code == "TYPOSQUAT" for s in getattr(c, "signals", []))
                for c in target_candidates
            )
            has_susp_tld = any(
                self._is_suspicious_tld(c.effective_host, c.registrable_domain)
                or any(s.code == "SUSPICIOUS_TLD" for s in getattr(c, "signals", []))
                for c in target_candidates
            )
            has_free_host = any(
                self._is_free_hosting(c.effective_host, c.registrable_domain)
                or any(s.code == "FREE_HOSTING" for s in getattr(c, "signals", []))
                for c in target_candidates
            )
            has_lure = any(
                any(s.code in ("LURE_KEYWORD_DOMAIN", "LURE_KEYWORD_PATH") for s in getattr(c, "signals", []))
                for c in target_candidates
            )
            has_passive_new = any(
                any(s.code in ("DOMAIN_NEW", "CERT_NEW") for s in getattr(c, "signals", []))
                for c in target_candidates
            )
            # Đích / children có rủi ro đáng ngờ
            has_dest_risk = any(getattr(ch, "url_risk_score", 0) >= 30 for ch in finding.children)

            if (
                has_brand
                or has_typosquat
                or has_susp_tld
                or has_free_host
                or has_lure
                or has_passive_new
                or has_dest_risk
            ):
                if not any(s.code == "CLOAKING_SUSPECTED" for s in finding.signals):
                    finding.signals.append(
                        UrlSignal(
                            code="CLOAKING_SUSPECTED",
                            severity="medium",
                            weight=25,
                            message_vi="Trang chặn công cụ kiểm tra tự động và có dấu hiệu giả mạo.",
                            evidence=f"antibot={chain.antibot.get('vendor')}, suspicious_context=True",
                        )
                    )

        # Recalculate score & verdict:
        # domain OFFICIAL + antibot vẫn 'official' (không cộng);
        if finding.is_official or (is_dest_official and not finding.signals):
            finding.url_risk_score = 0
            finding.verdict = "official"
        else:
            self_risk = min(99, sum(s.weight for s in finding.signals))
            max_child_risk = max((ch.url_risk_score for ch in finding.children), default=0)
            final_risk = max(self_risk, max_child_risk)
            finding.url_risk_score = final_risk

            # (e) không đọc được nội dung (antibot hoặc error timeout/blocked/budget/invalid_location)
            # => finding.verdict='unverified' khi các tín hiệu khác chưa đủ nâng lên suspicious/dangerous,
            cannot_read = (
                has_antibot
                or (getattr(chain, "error", None) in ("budget_exceeded", "request_timeout", "dns_timeout", "too_many_hops", "invalid_location"))
                or (bool(getattr(chain, "blocked_reason", None)) and chain.blocked_reason != "not_a_shortener")
            )

            if final_risk >= 70:
                finding.verdict = "dangerous"
            elif final_risk >= 40:
                finding.verdict = "suspicious"
            elif cannot_read:
                finding.verdict = "unverified"
            else:
                finding.verdict = "low" if final_risk >= 1 else "benign"

    def _analyze_passive(
        self,
        finding: UrlFinding,
        deadline_s: float = 5.0,
        recorder: Any = None,
    ) -> None:
        """
        Query passive intelligence (RDAP age, crt.sh first seen, TLS probe, DNS status)
        and append passive security signals to finding.
        Never adds risk signals to official domains.
        """
        if finding.is_official:
            return

        intel = self._get_passive_intel()
        try:
            try:
                res = intel.analyze(finding, deadline_s=deadline_s, recorder=recorder)
            except TypeError:
                try:
                    res = intel.analyze(finding, deadline_s=deadline_s)
                except TypeError:
                    res = intel.analyze(finding)
        except Exception as ex:
            finding.errors.append(f"passive_intel_error:{type(ex).__name__}")
            return

        if not res or not isinstance(res, dict):
            return

        finding.passive_intel = res
        finding.network_used = True

        # Check if platform domain or free hosting
        is_platform = self._is_platform_domain(finding.effective_host, finding.registrable_domain)
        is_free_host = self._is_free_hosting(finding.effective_host, finding.registrable_domain)

        # 1. DOMAIN_NEW (only when not platform / free hosting where registrable domain is platform domain)
        age_data = res.get("domain_age")
        if age_data and isinstance(age_data, dict) and not (is_platform or is_free_host):
            age_days = age_data.get("age_days")
            if age_days is not None and isinstance(age_days, int):
                if age_days < 7:
                    if not any(s.code == "DOMAIN_NEW" for s in finding.signals):
                        finding.signals.append(
                            UrlSignal(
                                code="DOMAIN_NEW",
                                severity="high",
                                weight=40,
                                message_vi=f"Tên miền mới được đăng ký ({age_days} ngày trước), nguy cơ lừa đảo rất cao.",
                                evidence=f"age_days={age_days}, created={age_data.get('created')}",
                            )
                        )
                elif age_days < 30:
                    if not any(s.code == "DOMAIN_NEW" for s in finding.signals):
                        finding.signals.append(
                            UrlSignal(
                                code="DOMAIN_NEW",
                                severity="medium",
                                weight=30,
                                message_vi=f"Tên miền mới được đăng ký ({age_days} ngày trước), nguy cơ lừa đảo cao.",
                                evidence=f"age_days={age_days}, created={age_data.get('created')}",
                            )
                        )

        # 2. TLS Probe signals: CERT_NEW or CERT_INVALID
        tls_data = res.get("tls")
        if tls_data and isinstance(tls_data, dict):
            if tls_data.get("valid") is True:
                days_issued = tls_data.get("days_since_issued")
                if days_issued is not None and isinstance(days_issued, int) and days_issued < 7:
                    if not any(s.code == "CERT_NEW" for s in finding.signals):
                        finding.signals.append(
                            UrlSignal(
                                code="CERT_NEW",
                                severity="medium",
                                weight=25,
                                message_vi=f"Chứng chỉ SSL/TLS mới được cấp ({days_issued} ngày trước).",
                                evidence=f"days_since_issued={days_issued}, not_before={tls_data.get('not_before')}",
                            )
                        )
            elif tls_data.get("valid") is False:
                reason = tls_data.get("reason", "other")
                reason_map = {
                    "self_signed": "chứng chỉ tự ký",
                    "expired": "chứng chỉ đã hết hạn",
                    "hostname_mismatch": "tên miền không khớp với chứng chỉ",
                    "untrusted": "chứng chỉ không được tin cậy",
                    "other": "chứng chỉ không hợp lệ",
                }
                reason_vi = reason_map.get(reason, "chứng chỉ không hợp lệ")
                if not any(s.code == "CERT_INVALID" for s in finding.signals):
                    finding.signals.append(
                        UrlSignal(
                            code="CERT_INVALID",
                            severity="medium",
                            weight=25,
                            message_vi=f"Chứng chỉ bảo mật TLS không hợp lệ ({reason_vi}).",
                            evidence=f"reason={reason}",
                        )
                    )

        # 3. DOMAIN_DEAD
        dns_status = res.get("dns_status")
        if dns_status == "nxdomain":
            if not any(s.code == "DOMAIN_DEAD" for s in finding.signals):
                finding.signals.append(
                    UrlSignal(
                        code="DOMAIN_DEAD",
                        severity="low",
                        weight=10,
                        message_vi="Tên miền không còn phân giải; link có thể đã bị gỡ.",
                        evidence="dns_status=nxdomain",
                    )
                )

        # 4. CT_FIRST_SEEN_RECENT (chứng chỉ đầu tiên < 14 ngày và cert_count <= 3: weight 15)
        ct_data = res.get("ct")
        if ct_data and isinstance(ct_data, dict) and not (is_platform or is_free_host):
            first_seen_str = ct_data.get("first_seen")
            cert_count = ct_data.get("cert_count", 0)
            if first_seen_str:
                try:
                    from datetime import datetime, timezone
                    from codebase.url_analysis.passive import _parse_iso_date
                    dt = _parse_iso_date(first_seen_str)
                    if dt:
                        now_dt = datetime.now(timezone.utc)
                        days_fs = max(0, int((now_dt - dt).total_seconds() // 86400))
                        if days_fs < 14 and cert_count <= 3:
                            if not any(s.code == "CT_FIRST_SEEN_RECENT" for s in finding.signals):
                                finding.signals.append(
                                    UrlSignal(
                                        code="CT_FIRST_SEEN_RECENT",
                                        severity="low",
                                        weight=15,
                                        message_vi=f"Tên miền mới xuất hiện trên Certificate Transparency gần đây ({days_fs} ngày trước, {cert_count} chứng chỉ).",
                                        evidence=f"days_first_seen={days_fs}, cert_count={cert_count}",
                                    )
                                )
                except Exception:
                    pass

        # 5. Check antibot combination with DOMAIN_NEW or CERT_NEW:
        # CLOAKING_SUSPECTED (+25) có thể dùng DOMAIN_NEW/CERT_NEW như yếu tố phụ (chỉ khi không official)
        has_antibot = any(s.code == "ANTIBOT_CHALLENGE" for s in finding.signals)
        has_new_passive = any(s.code in ("DOMAIN_NEW", "CERT_NEW") for s in finding.signals)
        is_dest_official = (
            finding.is_official
            or any(getattr(ch, "is_official", False) for ch in finding.children)
            or (bool(finding.final_url) and self._is_dest_official(finding.final_url))
        )
        if has_antibot and has_new_passive and not is_dest_official:
            if not any(s.code == "CLOAKING_SUSPECTED" for s in finding.signals):
                finding.signals.append(
                    UrlSignal(
                        code="CLOAKING_SUSPECTED",
                        severity="medium",
                        weight=25,
                        message_vi="Trang chặn công cụ kiểm tra tự động và có dấu hiệu giả mạo.",
                        evidence="antibot + recent_domain_or_cert",
                    )
                )

        # Recalculate score & verdict
        if finding.is_official:
            finding.url_risk_score = 0
            finding.verdict = "official"
        elif is_dest_official and not finding.brand_match:
            finding.url_risk_score = 0
            finding.verdict = "official"
        else:
            self_risk = min(99, sum(s.weight for s in finding.signals))
            max_child_risk = max((ch.url_risk_score for ch in finding.children), default=0)
            final_risk = max(self_risk, max_child_risk)
            finding.url_risk_score = final_risk

            last_hop = finding.redirect_chain[-1] if getattr(finding, "redirect_chain", None) else None
            last_err = last_hop.get("error") if isinstance(last_hop, dict) else getattr(last_hop, "error", None)

            cannot_read = (
                any(s.code == "ANTIBOT_CHALLENGE" for s in finding.signals)
                or (last_err in ("budget_exceeded", "request_timeout", "dns_timeout", "too_many_hops", "invalid_location"))
                or any("timeout" in e or "budget" in e for e in getattr(finding, "errors", []))
                or getattr(finding, "verdict", None) == "unverified"
            )

            if final_risk >= 70:
                finding.verdict = "dangerous"
            elif final_risk >= 40:
                finding.verdict = "suspicious"
            elif cannot_read:
                finding.verdict = "unverified"
            else:
                # Rule: DOMAIN_DEAD never benign or official!
                finding.verdict = "low" if final_risk >= 1 else "benign"

    def analyze_text(
        self,
        text: str,
        extra_urls: list[tuple[str, str]] | None = None,
        allow_network: bool = False,
        deadline_s: float = 6.0,
        recorder: Any = None,
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

            def _quick_suspicion(cand: Any) -> int:
                raw_cand = cand.raw if hasattr(cand, "raw") else str(cand)
                raw_c_low = raw_cand.lower()
                sc = 0
                if "@" in raw_cand:
                    sc += 25
                if "xn--" in raw_c_low:
                    sc += 25
                if "%" in raw_cand:
                    sc += 20
                if "\\" in raw_cand:
                    sc += 20
                if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw_cand):
                    sc += 30
                if any(s in raw_c_low for s in self.shorteners):
                    sc += 20
                if any(fh in raw_c_low for fh in self.free_hosting):
                    sc += 20
                for st in self.suspicious_tlds:
                    if f".{st}" in raw_c_low:
                        sc += 25
                        break
                if any(p in raw_c_low for p in ("url=", "redirect=", "link=", "dest=", "target=", "q=", "continue=", "adurl=")):
                    sc += 20
                if any(t in raw_c_low for t in self.lure_tokens):
                    sc += 25
                if any(d in raw_c_low for d in ("hxxp", "[.]", "[:]", "[dot]", "(dot)")):
                    sc += 20
                if any(k in raw_c_low for k in ("vietcombank", "vcb", "techcombank", "agribank", "bidv", "momo", "zalo", "shopee")):
                    sc += 20
                if getattr(cand, "source", "") in ("markdown", "anchor") and getattr(cand, "display_text", None):
                    sc += 10
                return sc

            total_cands = len(candidates)
            has_url_flood = total_cands > 20
            if has_url_flood:
                indexed = list(enumerate(candidates))
                indexed.sort(key=lambda it: (-_quick_suspicion(it[1]), it[0]))
                candidates_to_analyze = [it[1] for it in indexed[:20]]
                is_truncated = True
            else:
                candidates_to_analyze = list(candidates)
                is_truncated = text_truncated or getattr(candidates, "truncated", False)

            # 3. Analyze each candidate
            findings: list[UrlFinding] = []
            for cand in candidates_to_analyze:
                if (time.perf_counter() - start_time) > deadline_s:
                    is_truncated = True
                    break
                f = self.analyze_url(
                    cand.raw,
                    source=cand.source,
                    display_text=cand.display_text,
                    allow_network=False,
                    depth=0,
                    obfuscation_steps=norm_steps,
                )
                findings.append(f)

            if has_url_flood and findings:
                flood_sig = UrlSignal(
                    code="URL_FLOOD",
                    severity="medium",
                    weight=20,
                    message_vi="Tin chứa quá nhiều đường link, một số chưa được kiểm tra.",
                    evidence=f"total_candidates={total_cands}, analyzed={len(findings)}",
                )
                findings[0].signals.append(flood_sig)
                findings[0].url_risk_score = min(99, max(findings[0].url_risk_score, 20))
                if findings[0].verdict in ("benign", "official"):
                    findings[0].verdict = "suspicious" if findings[0].url_risk_score >= 40 else "low"

            # 3.5 Network resolution for eligible findings (max 3 most suspicious / shorteners)
            if self._is_network_permitted(allow_network):
                res = self._get_resolver()
                eligible: list[UrlFinding] = []
                for f in findings:
                    p = parse_url(f.raw)
                    try:
                        if res.should_resolve(p):
                            eligible.append(f)
                    except Exception:
                        pass

                def _res_priority(f: UrlFinding) -> tuple[int, int]:
                    is_short = (
                        1
                        if (
                            self._is_shortener(f.effective_host)
                            or any(s.code == "SHORTENER" for s in f.signals)
                        )
                        else 0
                    )
                    return (is_short, f.url_risk_score)

                eligible.sort(key=_res_priority, reverse=True)
                to_resolve = eligible[:3]

                for f in to_resolve:
                    elapsed = time.perf_counter() - start_time
                    if elapsed >= deadline_s:
                        is_truncated = True
                        if recorder:
                            recorder.record("resolver_lookup", f.effective_host, status="skipped")
                        break
                    rem_time = max(0.01, deadline_s - elapsed)
                    try:
                        self._resolve_finding(f, res, deadline_s=rem_time, depth=0, recorder=recorder)
                    except Exception as ex:
                        f.errors.append(f"resolver_unhandled:{type(ex).__name__}")

            # 3.6 Passive intelligence for eligible findings (max 3 non-official with risk >= 15 or antibot or resolved destination)
            if self._is_network_permitted(allow_network):
                passive_eligible: list[UrlFinding] = []
                all_candidates: list[UrlFinding] = []
                for f in findings:
                    all_candidates.append(f)
                    for ch in getattr(f, "children", []) or []:
                        all_candidates.append(ch)

                child_ids = {id(ch) for f in findings for ch in getattr(f, "children", []) or []}
                # Ưu tiên domain ĐÍCH của chain (is_child_target), sau đó theo điểm rủi ro cao nhất
                all_candidates.sort(
                    key=lambda item: (1 if id(item) in child_ids else 0, item.url_risk_score),
                    reverse=True,
                )

                seen_hosts: set[str] = set()
                for item in all_candidates:
                    if item.is_official or getattr(item, "verdict", None) == "official":
                        continue
                    host = (item.effective_host or "").lower()
                    if not host:
                        continue
                    # Bỏ chính domain shortener ra khỏi danh sách passive
                    if self._is_shortener(host):
                        continue
                    if host in seen_hosts:
                        continue

                    has_antibot = any(s.code == "ANTIBOT_CHALLENGE" for s in item.signals) or bool(getattr(item, "redirect_chain", None))
                    is_child_target = id(item) in child_ids
                    if item.url_risk_score >= 15 or has_antibot or is_child_target:
                        passive_eligible.append(item)
                        seen_hosts.add(host)

                to_passive = passive_eligible[:3]

                for f in to_passive:
                    elapsed = time.perf_counter() - start_time
                    rem_time = deadline_s - elapsed
                    if rem_time < 0.3:
                        is_truncated = True
                        if recorder:
                            recorder.record("passive_lookup", f.effective_host or f.registrable_domain, status="skipped")
                        continue
                    try:
                        self._analyze_passive(f, deadline_s=rem_time, recorder=recorder)
                    except Exception as ex:
                        f.errors.append(f"passive_unhandled:{type(ex).__name__}")

                # If child findings were updated, re-calculate parents' risk scores
                for f in findings:
                    if f.children:
                        if f.is_official or getattr(f, "verdict", None) == "official":
                            f.url_risk_score = 0
                            f.verdict = "official"
                        else:
                            self_risk = min(99, sum(s.weight for s in f.signals))
                            max_child_risk = max((ch.url_risk_score for ch in f.children), default=0)
                            f.url_risk_score = max(self_risk, max_child_risk)
                            if f.url_risk_score >= 70:
                                f.verdict = "dangerous"
                            elif f.url_risk_score >= 40:
                                f.verdict = "suspicious"

            # 4. Aggregates
            max_url_risk = max((f.url_risk_score for f in findings), default=0)
            if has_url_flood:
                max_url_risk = max(max_url_risk, 20)

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

            # has_only_official_urls: True if all findings (and children) are official and no unverified URL flood
            def _all_official(flist: list[UrlFinding]) -> bool:
                for f in flist:
                    if not f.is_official or f.verdict == "unverified":
                        return False
                    if f.children and not _all_official(f.children):
                        return False
                return True

            has_only_official = _all_official(findings) if (findings and not has_url_flood) else False

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

            if has_url_flood:
                flood_msg = "Tin chứa quá nhiều đường link, một số chưa được kiểm tra."
                if flood_msg not in summary_vi:
                    summary_vi.append(flood_msg)

            def _has_antibot_sig(finding_item: UrlFinding) -> bool:
                if any(s.code == "ANTIBOT_CHALLENGE" for s in finding_item.signals):
                    return True
                return any(any(s.code == "ANTIBOT_CHALLENGE" for s in getattr(ch, "signals", [])) for ch in getattr(finding_item, "children", []))

            unverified_list = [f for f in findings if f.verdict == "unverified"]
            if unverified_list:
                has_antibot_unverified = any(_has_antibot_sig(f) for f in unverified_list)
                has_network_unverified = any(not _has_antibot_sig(f) for f in unverified_list)

                if has_antibot_unverified:
                    antibot_msg = "Trang này chặn công cụ kiểm tra tự động nên hệ thống chưa xác minh được nội dung. Điều này KHÔNG có nghĩa là an toàn."
                    if antibot_msg not in summary_vi:
                        summary_vi.append(antibot_msg)

                if has_network_unverified:
                    net_unverified_msg = "Không kiểm tra được nội dung do lỗi kết nối hoặc hết thời gian. Điều này KHÔNG có nghĩa là an toàn."
                    if net_unverified_msg not in summary_vi:
                        summary_vi.append(net_unverified_msg)

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
                summary_vi=[f"Lỗi khi phân tích liên kết: {type(e).__name__}"],
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
        deadline_s: float = 6.0,
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
        if not is_off and hasattr(self.catalog, "is_related"):
            is_rel, rel_brand = self.catalog.is_related(effective_host)
            if is_rel:
                is_off = True
                off_brand = rel_brand

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
        raw_low = raw.lower()
        p_low = (parsed.path or "").lower()
        q_low = (parsed.query or "").lower()
        h_low = effective_host.lower()

        apk_exts = (".apk", ".xapk", ".apks")
        has_apk = False
        if any(ext in raw_low for ext in apk_exts):
            has_apk = (
                p_low.endswith(apk_exts)
                or any(f"{ext}?" in raw_low or f"{ext}&" in raw_low or f"{ext};" in raw_low or f"{ext}#" in raw_low for ext in apk_exts)
                or any(f"{ext}/" in p_low or f"{ext};" in p_low for ext in apk_exts)
                or h_low.endswith(".apk")
            )
            if not has_apk and q_low:
                try:
                    for _, q_val in urllib.parse.parse_qsl(q_low, keep_blank_values=True):
                        v_clean = q_val.split(";")[0].strip()
                        if any(v_clean.endswith(ext) for ext in apk_exts):
                            has_apk = True
                            break
                except Exception:
                    pass

            if not has_apk:
                if re.search(r"(?:[?&;=]|^)[^&;]*\.(?:apk|xapk|apks)(?=[?&#;&\s]|$)", raw_low):
                    has_apk = True

        if has_apk:
            add_sig(
                "APK_DOWNLOAD",
                "critical",
                60,
                "Đường dẫn trực tiếp tải về tệp ứng dụng Android (.apk) tiềm ẩn mã độc.",
                f"url={raw}",
            )

        # Signal: ARCHIVE DOWNLOAD on non-official domains
        if not is_off:
            archive_exts = (".zip", ".rar", ".7z", ".iso")
            exec_exts = (".exe", ".msi", ".scr", ".bat", ".js", ".jar")

            def _check_ext_match(target_exts: tuple[str, ...]) -> str | None:
                if not any(ext in raw_low for ext in target_exts):
                    return None
                for ext in target_exts:
                    if p_low.endswith(ext) or f"{ext}?" in raw_low or f"{ext}&" in raw_low or f"{ext};" in raw_low or f"{ext}#" in raw_low:
                        return ext
                    if f"{ext}/" in p_low or f"{ext};" in p_low:
                        return ext
                if q_low:
                    try:
                        for _, q_val in urllib.parse.parse_qsl(q_low, keep_blank_values=True):
                            v_clean = q_val.split(";")[0].strip()
                            for ext in target_exts:
                                if v_clean.endswith(ext):
                                    return ext
                    except Exception:
                        pass
                m = re.search(r"(?:[?&;=]|^)[^&;]*\.(" + "|".join(e.lstrip(".") for e in target_exts) + r")(?=[?&#;&\s]|$)", raw_low)
                if m:
                    return "." + m.group(1).lower()
                return None

            exec_match = _check_ext_match(exec_exts)
            if exec_match:
                add_sig(
                    "ARCHIVE_DOWNLOAD",
                    "high",
                    40,
                    f"Đường dẫn tải về tệp thực thi/kịch bản nguy hiểm ({exec_match}) trên tên miền không chính thức.",
                    f"ext={exec_match}, url={raw}",
                )
            else:
                arch_match = _check_ext_match(archive_exts)
                if arch_match:
                    add_sig(
                        "ARCHIVE_DOWNLOAD",
                        "medium",
                        25,
                        f"Đường dẫn tải về tệp nén ({arch_match}) trên tên miền không chính thức, tiềm ẩn mã độc.",
                        f"ext={arch_match}, url={raw}",
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

        # Signal: INVALID HOST LENGTH (DNS standard limit: max 253 chars, max 63 chars per label)
        eff_h = effective_host or ""
        disp_h = display_host or ""
        is_invalid_host_len = (
            len(eff_h) > 253
            or any(len(lbl) > 63 for lbl in eff_h.split("."))
            or (bool(disp_h) and (len(disp_h) > 253 or any(len(lbl) > 63 for lbl in disp_h.split("."))))
        )
        if is_invalid_host_len:
            if "INVALID_HOST_LENGTH" not in parsed.flags:
                parsed.flags.append("INVALID_HOST_LENGTH")
            add_sig(
                "INVALID_HOST_LENGTH",
                "low",
                15,
                "Tên miền có độ dài vượt quá giới hạn chuẩn DNS (tối đa 253 ký tự hoặc 63 ký tự mỗi nhãn).",
                f"host_len={len(eff_h)}",
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

        # Normalized URL (canonical scheme, effective host, path, query, fragment)
        scheme_prefix = f"{parsed.scheme}://" if parsed.scheme else "http://"
        norm_url = f"{scheme_prefix}{effective_host}{parsed.path}"
        if parsed.query:
            norm_url += f"?{parsed.query}"
        if parsed.fragment:
            norm_url += f"#{parsed.fragment}"

        # Destination URL after redirect peeling or embedded extraction
        final_dest = children[-1].final_url if children else norm_url

        finding = UrlFinding(
            raw=raw,
            normalized=norm_url,
            final_url=final_dest,
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

        if self._is_network_permitted(allow_network) and depth < 2:
            res = self._get_resolver()
            try:
                if res.should_resolve(parsed):
                    self._resolve_finding(finding, res, deadline_s=deadline_s, depth=depth)
            except Exception as ex:
                finding.errors.append(f"resolver_unhandled:{type(ex).__name__}")

        if self._is_network_permitted(allow_network) and depth == 0 and not finding.is_official:
            has_antibot = any(s.code == "ANTIBOT_CHALLENGE" for s in finding.signals) or bool(getattr(finding, "redirect_chain", None))
            has_shortener = self._is_shortener(finding.effective_host) or any(
                s.code in ("SHORTENER", "SHORTENER_RESOLVED") for s in finding.signals
            )
            if finding.url_risk_score >= 15 or has_antibot or has_shortener:
                try:
                    self._analyze_passive(finding, deadline_s=deadline_s)
                except Exception as ex:
                    finding.errors.append(f"passive_unhandled:{type(ex).__name__}")

        return finding
