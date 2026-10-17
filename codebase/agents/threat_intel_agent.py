import collections
import os
import json
import time
import re
import threading
import urllib.request
import urllib.parse
import urllib.error
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from codebase.config import get_settings, get_api_key


class ThreatIntelAgent:
    """
    Threat Intelligence Agent for SafeGuard AI.

    Integrates with multiple global threat databases to perform real-time
    URL/domain/IP reputation lookups:

    ┌─────────────────────────────────────────────────────────────┐
    │  VirusTotal     — 90+ AV engines, URL/domain/IP scanner     │
    │  Google Safe Browsing — Google's phishing/malware blacklist │
    │  URLScan.io     — Screenshot + DNS + behavior analysis      │
    │  PhishTank      — Crowdsourced 5M+ phishing URLs (no key)  │
    └─────────────────────────────────────────────────────────────┘

    All lookups are timeout-safe and fail gracefully when keys are missing.
    """

    TIMEOUT = 3.0  # seconds per API call (Phase 3 requirement: 3s)
    CACHE_MAX = 512
    CACHE_TTL_NORMAL = 21600  # 6 hours (in seconds)
    CACHE_TTL_ERROR = 60      # 60 seconds for errors / timeouts

    def __init__(self):
        settings = get_settings()
        self.vt_key = get_api_key("VIRUSTOTAL_API_KEY")
        self.gsb_key = get_api_key("GOOGLE_SAFE_BROWSING_KEY")
        self.urlscan_key = get_api_key("URLSCAN_API_KEY")

        self._cache: collections.OrderedDict[str, tuple[dict, float]] = collections.OrderedDict()
        self._cache_lock = threading.Lock()

        if settings.offline or not settings.network_enabled:
            print("[ThreatIntelAgent] [INFO] ThreatIntel disabled (offline or network disabled).")
            return

        active = []
        if self.vt_key:
            active.append("VirusTotal")
        if self.gsb_key:
            active.append("Google Safe Browsing")
        if self.urlscan_key:
            active.append("URLScan.io")
        if settings.phishtank_enabled:
            active.append("PhishTank")

        print(f"[ThreatIntelAgent] [OK] Active sources: {', '.join(active)}")

    def _normalize_cache_key(self, url: str) -> str:
        """Normalize URL for consistent cache lookup while protecting privacy."""
        if not url:
            return ""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            parsed = urllib.parse.urlsplit(url)
            scheme = (parsed.scheme or "https").lower()
            netloc = (parsed.netloc or "").lower()
            if "@" in netloc:
                netloc = netloc.split("@")[-1]
            if ":" in netloc and not netloc.startswith("["):
                parts = netloc.split(":")
                if (scheme == "http" and parts[1] == "80") or (scheme == "https" and parts[1] == "443"):
                    netloc = parts[0]
            path = parsed.path.rstrip("/") or "/"
            return f"{scheme}://{netloc}{path}"
        except Exception:
            return url.lower().strip().rstrip("/")

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────
    def scan_url(
        self,
        url: str,
        *,
        deadline_s: float | None = None,
        recorder: Any = None,
    ) -> dict:
        """
        Scan a URL against all available threat intelligence sources in parallel.
        Returns aggregated verdict with per-source details and network_actions.
        """
        url = url.strip()
        if not url:
            return {
                "error": "Empty URL",
                "is_malicious": False,
                "sources_checked": [],
                "network_actions": []
            }

        # Normalize URL scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        domain = self._extract_domain(url)
        settings = get_settings()
        if settings.offline or not settings.network_enabled:
            return {
                "url": url,
                "domain": domain,
                "is_malicious": False,
                "malicious_sources": 0,
                "sources_checked": [],
                "verdict_summary": "Offline / mạng bị tắt",
                "details": {},
                "network_actions": []
            }

        # Check Cache (TTL 6h for normal, 60s for error/timeout)
        cache_key = self._normalize_cache_key(url)
        with self._cache_lock:
            if cache_key in self._cache:
                cached_val, expires_at = self._cache[cache_key]
                if time.time() < expires_at:
                    self._cache.move_to_end(cache_key)
                    cached_res = dict(cached_val)
                    # Cache hit: no network calls performed in this run
                    cached_res["network_actions"] = []
                    return cached_res

        # Privacy cleanup for external lookups: strip userinfo, query, fragment
        clean_url = f"https://{domain}/"

        results = {}
        sources_checked = []
        network_actions = []

        call_timeout = min(self.TIMEOUT, deadline_s) if deadline_s is not None else self.TIMEOUT
        if call_timeout <= 0:
            return {
                "url": url,
                "domain": domain,
                "is_malicious": False,
                "malicious_sources": 0,
                "sources_checked": [],
                "verdict_summary": "Không phát hiện mối đe dọa (hết thời gian)",
                "details": {src: {"error": "timeout", "is_malicious": False} for src in ("virustotal", "google_safe_browsing", "urlscan", "phishtank")},
                "network_actions": []
            }

        # Run all checks in parallel with ThreadPoolExecutor without 'with' block
        def _safe_call(fn, *args, timeout: float = 3.0):
            try:
                return fn(*args, timeout=timeout)
            except TypeError:
                return fn(*args)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        try:
            futures = {}

            if self.vt_key:
                r_idx = recorder.record_request("virustotal_lookup", domain) if recorder is not None else None
                futures[executor.submit(_safe_call, self._check_virustotal, domain, timeout=call_timeout)] = ("virustotal", r_idx)
                network_actions.append({"type": "virustotal_lookup", "target": domain})
            if self.gsb_key:
                r_idx = recorder.record_request("gsb_lookup", domain) if recorder is not None else None
                futures[executor.submit(_safe_call, self._check_google_safe_browsing, [clean_url], timeout=call_timeout)] = ("google_safe_browsing", r_idx)
                network_actions.append({"type": "gsb_lookup", "target": domain})
            if self.urlscan_key:
                r_idx = recorder.record_request("urlscan_search", domain) if recorder is not None else None
                futures[executor.submit(_safe_call, self._check_urlscan, clean_url, timeout=call_timeout)] = ("urlscan", r_idx)
                network_actions.append({"type": "urlscan_search", "target": domain})

            if settings.phishtank_enabled:
                r_idx = recorder.record_request("phishtank_lookup", domain) if recorder is not None else None
                futures[executor.submit(_safe_call, self._check_phishtank, clean_url, timeout=call_timeout)] = ("phishtank", r_idx)
                network_actions.append({"type": "phishtank_lookup", "target": domain})

            # Wait with strict timeout
            done, not_done = concurrent.futures.wait(futures.keys(), timeout=call_timeout)

            for future in done:
                source_name, r_idx = futures[future]
                try:
                    result = future.result()
                    results[source_name] = result
                    sources_checked.append(source_name)
                    if r_idx is not None:
                        if result and result.get("error"):
                            recorder.update_status(r_idx, "error")
                        else:
                            recorder.update_status(r_idx, "ok")
                except Exception as e:
                    results[source_name] = {"error": type(e).__name__, "is_malicious": False}
                    if r_idx is not None:
                        recorder.update_status(r_idx, "error")

            for future in not_done:
                source_name, r_idx = futures[future]
                results[source_name] = {"error": "timeout", "is_malicious": False}
                if r_idx is not None:
                    recorder.update_status(r_idx, "timeout")

        finally:
            # Immediately shutdown without waiting and cancel any pending/running futures
            executor.shutdown(wait=False, cancel_futures=True)

        # Aggregate verdict
        is_malicious = any(
            results.get(src, {}).get("is_malicious", False)
            for src in results
        )
        malicious_count = sum(
            1 for src in results
            if results[src].get("is_malicious", False)
        )
        vt_positives = results.get("virustotal", {}).get("positives", 0)
        vt_total = results.get("virustotal", {}).get("total", 0)

        # Build summary
        verdict_parts = []
        if results.get("virustotal", {}).get("is_malicious"):
            verdict_parts.append(f"VirusTotal: {vt_positives}/{vt_total} engines phát hiện độc hại")
        if results.get("google_safe_browsing", {}).get("is_malicious"):
            threat_type = results["google_safe_browsing"].get("threat_type", "PHISHING")
            verdict_parts.append(f"Google Safe Browsing: {threat_type}")
        if results.get("urlscan", {}).get("is_malicious"):
            verdict_parts.append(f"URLScan.io: Phát hiện hành vi đáng ngờ")
        if results.get("phishtank", {}).get("is_malicious"):
            verdict_parts.append(f"PhishTank: URL có trong database lừa đảo")

        # Determine cache TTL: 60s if all failed or timed out, 6h if normal
        is_error = False
        if not sources_checked and results:
            is_error = True
        elif results and all(v.get("error") for v in results.values()):
            is_error = True

        ttl = self.CACHE_TTL_ERROR if is_error else self.CACHE_TTL_NORMAL

        res_dict = {
            "url": url,
            "domain": domain,
            "is_malicious": is_malicious,
            "malicious_sources": malicious_count,
            "sources_checked": sources_checked,
            "verdict_summary": " | ".join(verdict_parts) if verdict_parts else "Không phát hiện mối đe dọa",
            "details": results,
            "network_actions": network_actions
        }

        # Store in cache
        with self._cache_lock:
            if len(self._cache) >= self.CACHE_MAX:
                self._cache.popitem(last=False)
            self._cache[cache_key] = (res_dict, time.time() + ttl)

        return res_dict

    def lookup_domain(self, domain: str) -> dict:
        """
        Lookup domain info: age, registrar, URLScan analysis.
        Newly registered domains (< 30 days) are high risk.
        """
        domain = domain.strip().lower()
        result = {
            "domain": domain,
            "is_suspicious": False,
            "age_days": None,
            "registrar": None,
            "urlscan_verdict": None
        }

        target_host = self._extract_domain(domain)
        if not target_host:
            target_host = domain

        settings = get_settings()
        # URLScan.io domain lookup (only when online and network enabled)
        if not (settings.offline or not settings.network_enabled) and self.urlscan_key:
            try:
                urlscan_res = self._urlscan_search_domain(domain)
                result["urlscan_verdict"] = urlscan_res
                if urlscan_res.get("malicious"):
                    result["is_suspicious"] = True
            except Exception as e:
                result["urlscan_error"] = str(e)

        # Check official whitelist via BrandCatalog
        is_official = False
        try:
            from codebase.url_analysis.brands import BrandCatalog
            catalog = BrandCatalog.load()
            is_off, brand = catalog.is_official(target_host)
            if is_off:
                is_official = True
        except Exception:
            pass

        if not is_official:
            from codebase.agents.explainable_agent import OFFICIAL_WHITELIST_DOMAINS
            for official in OFFICIAL_WHITELIST_DOMAINS:
                if target_host == official or target_host.endswith("." + official):
                    is_official = True
                    break

        if is_official:
            result["is_suspicious"] = False
            result["is_official"] = True
            result["reason"] = f"Tên miền chính thức hợp pháp thuộc Whitelist (Official): {domain}"
            return result

        # Heuristic: suspicious TLDs (exact suffix matching) + impersonation patterns
        try:
            from codebase.url_analysis.normalize import load_url_lists
            _lists = load_url_lists()
            raw_tlds = _lists.get("suspicious_tlds", [])
            suspicious_tlds = {f".{t.lower().lstrip('.')}" for t in raw_tlds if t}
        except Exception:
            suspicious_tlds = {".xyz", ".cc", ".tk", ".ml", ".ga", ".cf", ".info", ".top", ".pw"}

        impersonation = [
            "vietcombank-", "techcombank-", "agribank-", "vneid-",
            "bankingvn", "banking-vn", "chinhphu-", "canhsat-", "mofa-"
        ]
        if any(target_host.endswith(tld) for tld in suspicious_tlds):
            result["is_suspicious"] = True
            result["reason"] = f"TLD đáng ngờ trong domain: {domain}"
        if any(p in target_host for p in impersonation):
            result["is_suspicious"] = True
            result["reason"] = f"Domain giả mạo tổ chức/ngân hàng: {domain}"

        return result

    def check_phishtank_bulk(self, urls: list) -> dict:
        """Check multiple URLs against PhishTank database."""
        results = {}
        for url in urls[:5]:  # limit to 5 to avoid timeout
            results[url] = self._check_phishtank(url)
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # VIRUSTOTAL
    # ─────────────────────────────────────────────────────────────────────────
    def _check_virustotal(self, domain_or_url: str, *, timeout: float = 3.0) -> dict:
        """Query VirusTotal Domain scan API v3 (/domains/{host}, GET only, no URL path/query)."""
        if not self.vt_key:
            return {"is_malicious": False, "error": "No API key"}
        domain = self._extract_domain(domain_or_url)
        if not domain:
            return {"is_malicious": False, "error": "Empty domain"}
        try:
            api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"

            req = urllib.request.Request(
                api_url,
                headers={"x-apikey": self.vt_key, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            is_malicious = positives >= 2

            return {
                "is_malicious": is_malicious,
                "positives": positives,
                "total": total,
                "stats": stats,
                "permalink": f"https://www.virustotal.com/gui/domain/{domain}"
            }

        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"is_malicious": False, "status": "not_found", "message": "Domain not scanned"}
            return {"is_malicious": False, "error": type(e).__name__}
        except Exception as e:
            return {"is_malicious": False, "error": type(e).__name__}

    # ─────────────────────────────────────────────────────────────────────────
    # GOOGLE SAFE BROWSING
    # ─────────────────────────────────────────────────────────────────────────
    def _check_google_safe_browsing(self, urls: list, *, timeout: float = 3.0) -> dict:
        """Query Google Safe Browsing API v4 with X-Goog-Api-Key header and scheme://host/ only."""
        if not self.gsb_key:
            return {"is_malicious": False, "error": "No API key"}
        try:
            api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            cleaned_urls = []
            for u in urls:
                try:
                    p = urllib.parse.urlsplit(u)
                    scheme = (p.scheme or "https").lower()
                    host = self._extract_domain(u)
                    cleaned_urls.append(f"{scheme}://{host}/")
                except Exception:
                    cleaned_urls.append(u)

            payload = json.dumps({
                "client": {"clientId": "safeguard-ai", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": cu} for cu in cleaned_urls]
                }
            }).encode()

            req = urllib.request.Request(
                api_url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Goog-Api-Key": self.gsb_key,
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())

            matches = data.get("matches", [])
            is_malicious = len(matches) > 0
            threat_type = matches[0].get("threatType", "") if matches else ""

            return {
                "is_malicious": is_malicious,
                "threat_type": threat_type,
                "matches": len(matches)
            }
        except Exception as e:
            return {"is_malicious": False, "error": type(e).__name__}

    # ─────────────────────────────────────────────────────────────────────────
    # URLSCAN.IO
    # ─────────────────────────────────────────────────────────────────────────
    def _check_urlscan(self, url: str, *, timeout: float = 3.0) -> dict:
        """
        URLScan.io check: search existing scans by domain: {domain}.
        """
        if not self.urlscan_key:
            return {"is_malicious": False, "error": "No API key"}
        try:
            domain = self._extract_domain(url)
            encoded = urllib.parse.quote(f"domain:{domain}")
            req = urllib.request.Request(
                f"https://urlscan.io/api/v1/search/?q={encoded}&size=5",
                headers={"API-Key": self.urlscan_key}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())

            results = data.get("results", [])
            malicious_count = sum(
                1 for r in results
                if r.get("verdicts", {}).get("overall", {}).get("malicious", False)
            )
            score = max([r.get("verdicts", {}).get("overall", {}).get("score", 0) for r in results], default=0)
            return {
                "is_malicious": malicious_count > 0,
                "score": score,
                "scan_count": len(results),
                "malicious_count": malicious_count
            }
        except Exception as e:
            return {"is_malicious": False, "error": type(e).__name__}

    def _urlscan_search_domain(self, domain: str) -> dict:
        """Search existing URLScan scans for a domain."""
        try:
            encoded = urllib.parse.quote(f"domain:{domain}")
            req = urllib.request.Request(
                f"https://urlscan.io/api/v1/search/?q={encoded}&size=5",
                headers={"API-Key": self.urlscan_key} if self.urlscan_key else {}
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                data = json.loads(resp.read().decode())

            results = data.get("results", [])
            malicious_count = sum(
                1 for r in results
                if r.get("verdicts", {}).get("overall", {}).get("malicious", False)
            )
            return {
                "malicious": malicious_count > 0,
                "scan_count": len(results),
                "malicious_count": malicious_count
            }
        except Exception as e:
            return {"malicious": False, "error": type(e).__name__}

    # ─────────────────────────────────────────────────────────────────────────
    # PHISHTANK (No API key required)
    # ─────────────────────────────────────────────────────────────────────────
    def _check_phishtank(self, url: str, *, timeout: float = 3.0) -> dict:
        """Query PhishTank API — disabled by default unless Settings.phishtank_enabled is True."""
        settings = get_settings()
        if settings.offline or not settings.network_enabled or not settings.phishtank_enabled:
            return {"is_malicious": False, "source": "phishtank", "note": "disabled"}

        try:
            p = urllib.parse.urlsplit(url)
            scheme = (p.scheme or "https").lower()
            host = self._extract_domain(url)
            clean_url = f"{scheme}://{host}/"

            api_url = "https://checkurl.phishtank.com/checkurl/"
            data = urllib.parse.urlencode({
                "url": clean_url,
                "format": "json",
                "app_key": ""
            }).encode()

            req = urllib.request.Request(
                api_url,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "SafeGuard-AI/1.0 (phishtank)"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result = json.loads(resp.read().decode())

            results = result.get("results", {})
            in_database = results.get("in_database", False)
            valid = results.get("valid", False)

            return {
                "is_malicious": in_database and valid,
                "in_database": in_database,
                "phish_id": results.get("phish_id", ""),
                "phish_detail_url": results.get("phish_detail_url", "")
            }
        except Exception as e:
            return {"is_malicious": False, "error": type(e).__name__}

    # ─────────────────────────────────────────────────────────────────────────
    # UTILS
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_domain(self, url: str) -> str:
        if not url:
            return ""
        try:
            from codebase.url_analysis.parse import parse_url
            parsed = parse_url(url)
            host = (parsed.effective_host or "").strip().lower()
            if host.startswith("www."):
                host = host[4:]
            return host if host else url.strip().lower()
        except Exception:
            try:
                parsed = urllib.parse.urlparse(url)
                netloc = parsed.netloc.lower()
                if "@" in netloc:
                    netloc = netloc.rsplit("@", 1)[1]
                if ":" in netloc:
                    netloc = netloc.split(":", 1)[0]
                if netloc.startswith("www."):
                    netloc = netloc[4:]
                return netloc if netloc else url.strip().lower()
            except Exception:
                return url

    def extract_urls_from_text(self, text: str) -> list:
        """Extract all URLs from a text string."""
        pattern = r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+'
        return list(set(re.findall(pattern, text, re.IGNORECASE)))


if __name__ == "__main__":
    agent = ThreatIntelAgent()

    # Test with a known suspicious URL pattern
    test_url = "https://vietcombank-bankingvn.com/login"
    print(f"\n[ThreatIntelAgent] Testing: {test_url}")
    result = agent.scan_url(test_url)
    print(f"  Is Malicious: {result['is_malicious']}")
    print(f"  Sources checked: {result['sources_checked']}")
    print(f"  Verdict: {result['verdict_summary']}")

    # Test domain lookup
    domain_result = agent.lookup_domain("vietcombank-bankingvn.com")
    print(f"\n[ThreatIntelAgent] Domain lookup: vietcombank-bankingvn.com")
    print(f"  Is Suspicious: {domain_result['is_suspicious']}")
