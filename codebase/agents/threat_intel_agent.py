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
        active.append("PhishTank")  # always available, no key needed

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
    def scan_url(self, url: str) -> dict:
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
        try:
            parsed = urllib.parse.urlsplit(url)
            clean_netloc = domain
            clean_path = parsed.path if parsed.path else "/"
            clean_url = urllib.parse.urlunsplit((parsed.scheme or "https", clean_netloc, clean_path, "", ""))
        except Exception:
            clean_url = f"https://{domain}/"

        results = {}
        sources_checked = []
        network_actions = []

        # Run all checks in parallel with ThreadPoolExecutor without 'with' block
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        try:
            futures = {}

            if self.vt_key:
                futures[executor.submit(self._check_virustotal, clean_url)] = "virustotal"
                network_actions.append({"type": "virustotal_lookup", "target": domain})
            if self.gsb_key:
                futures[executor.submit(self._check_google_safe_browsing, [clean_url])] = "google_safe_browsing"
                network_actions.append({"type": "gsb_lookup", "target": domain})
            if self.urlscan_key:
                futures[executor.submit(self._check_urlscan, clean_url)] = "urlscan"
                network_actions.append({"type": "urlscan_search", "target": domain})

            futures[executor.submit(self._check_phishtank, clean_url)] = "phishtank"
            network_actions.append({"type": "phishtank_lookup", "target": domain})

            # Wait with strict timeout (timeout 3.0s)
            done, not_done = concurrent.futures.wait(futures.keys(), timeout=self.TIMEOUT)

            for future in done:
                source_name = futures[future]
                try:
                    result = future.result()
                    results[source_name] = result
                    sources_checked.append(source_name)
                except Exception as e:
                    results[source_name] = {"error": str(e), "is_malicious": False}

            for future in not_done:
                source_name = futures[future]
                results[source_name] = {"error": "timeout", "is_malicious": False}

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
    def _check_virustotal(self, url: str) -> dict:
        """Query VirusTotal URL scan API v3 (GET by default, no submit unless VT_SUBMIT=1)."""
        if not self.vt_key:
            return {"is_malicious": False, "error": "No API key"}
        try:
            import base64
            # Encode URL to base64 (VT API v3 format, without padding '=')
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            req = urllib.request.Request(
                api_url,
                headers={"x-apikey": self.vt_key, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
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
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
            }

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Default: DO NOT submit URL. Only submit when VT_SUBMIT=1.
                if os.environ.get("VT_SUBMIT") == "1":
                    return self._submit_virustotal(url)
                return {"is_malicious": False, "status": "not_found", "message": "URL not scanned"}
            return {"is_malicious": False, "error": f"HTTP {e.code}"}
        except Exception as e:
            return {"is_malicious": False, "error": str(e)}

    def _submit_virustotal(self, url: str) -> dict:
        """Submit a new URL to VirusTotal for scanning."""
        try:
            data = urllib.parse.urlencode({"url": url}).encode()
            req = urllib.request.Request(
                "https://www.virustotal.com/api/v3/urls",
                data=data,
                headers={
                    "x-apikey": self.vt_key,
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                result = json.loads(resp.read().decode())
            return {
                "is_malicious": False,
                "status": "submitted",
                "analysis_id": result.get("data", {}).get("id", "")
            }
        except Exception as e:
            return {"is_malicious": False, "error": str(e)}

    # ─────────────────────────────────────────────────────────────────────────
    # GOOGLE SAFE BROWSING
    # ─────────────────────────────────────────────────────────────────────────
    def _check_google_safe_browsing(self, urls: list) -> dict:
        """Query Google Safe Browsing API v4 for a list of URLs (only when key valid)."""
        if not self.gsb_key:
            return {"is_malicious": False, "error": "No API key"}
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_key}"
            payload = json.dumps({
                "client": {"clientId": "safeguard-ai", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": u} for u in urls]
                }
            }).encode()

            req = urllib.request.Request(
                api_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
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
            return {"is_malicious": False, "error": str(e)}

    # ─────────────────────────────────────────────────────────────────────────
    # URLSCAN.IO
    # ─────────────────────────────────────────────────────────────────────────
    def _check_urlscan(self, url: str) -> dict:
        """
        URLScan.io check:
        - Default: ONLY search existing scans by domain (NO submit, no POST, privacy-preserving).
        - Submit: ONLY when URLSCAN_SUBMIT=1, with visibility='unlisted', and NO sleep(3).
        """
        if not self.urlscan_key:
            return {"is_malicious": False, "error": "No API key"}
        try:
            domain = self._extract_domain(url)
            if os.environ.get("URLSCAN_SUBMIT") == "1":
                # Submit scan with visibility 'unlisted'
                payload = json.dumps({"url": url, "visibility": "unlisted"}).encode()
                req = urllib.request.Request(
                    "https://urlscan.io/api/v1/scan/",
                    data=payload,
                    headers={
                        "API-Key": self.urlscan_key,
                        "Content-Type": "application/json"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                    data = json.loads(resp.read().decode())

                uuid = data.get("uuid", "")
                # No time.sleep(3) per Phase 3 requirement
                return {
                    "is_malicious": False,
                    "status": "submitted",
                    "uuid": uuid,
                    "result_url": f"https://urlscan.io/result/{uuid}/" if uuid else ""
                }
            else:
                # Default: Search existing scans for this domain (search API)
                encoded = urllib.parse.quote(f"domain:{domain}")
                req = urllib.request.Request(
                    f"https://urlscan.io/api/v1/search/?q={encoded}&size=5",
                    headers={"API-Key": self.urlscan_key}
                )
                with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
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
            return {"is_malicious": False, "error": str(e)}

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
            return {"malicious": False, "error": str(e)}

    # ─────────────────────────────────────────────────────────────────────────
    # PHISHTANK (No API key required)
    # ─────────────────────────────────────────────────────────────────────────
    def _check_phishtank(self, url: str) -> dict:
        """Query PhishTank API — no key required, public endpoint."""
        settings = get_settings()
        if settings.offline or not settings.network_enabled:
            return {"is_malicious": False, "source": "phishtank", "note": "offline"}

        try:
            encoded_url = urllib.parse.quote(url, safe="")
            api_url = "https://checkurl.phishtank.com/checkurl/"
            data = urllib.parse.urlencode({
                "url": url,
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
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
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
            return {"is_malicious": False, "error": str(e)}

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
