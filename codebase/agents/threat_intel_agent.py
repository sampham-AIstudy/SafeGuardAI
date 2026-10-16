import os
import json
import time
import re
import urllib.request
import urllib.parse
import urllib.error
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

    TIMEOUT = 8  # seconds per API call

    def __init__(self):
        settings = get_settings()
        self.vt_key = get_api_key("VIRUSTOTAL_API_KEY")
        self.gsb_key = get_api_key("GOOGLE_SAFE_BROWSING_KEY")
        self.urlscan_key = get_api_key("URLSCAN_API_KEY")

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

        print(f"[ThreatIntelAgent] ✅ Active sources: {', '.join(active)}")

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────
    def scan_url(self, url: str) -> dict:
        """
        Scan a URL against all available threat intelligence sources in parallel.
        Returns aggregated verdict with per-source details.
        """
        url = url.strip()
        if not url:
            return {"error": "Empty URL", "is_malicious": False, "sources_checked": []}

        # Normalize URL
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
                "details": {}
            }

        results = {}
        sources_checked = []

        # Run all checks in parallel for speed
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            if self.vt_key:
                futures[executor.submit(self._check_virustotal, url)] = "virustotal"
            if self.gsb_key:
                futures[executor.submit(self._check_google_safe_browsing, [url])] = "google_safe_browsing"
            if self.urlscan_key:
                futures[executor.submit(self._check_urlscan, url)] = "urlscan"
            futures[executor.submit(self._check_phishtank, url)] = "phishtank"

            for future in as_completed(futures, timeout=self.TIMEOUT + 2):
                source_name = futures[future]
                try:
                    result = future.result(timeout=self.TIMEOUT)
                    results[source_name] = result
                    sources_checked.append(source_name)
                except Exception as e:
                    results[source_name] = {"error": str(e), "is_malicious": False}

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

        return {
            "url": url,
            "domain": domain,
            "is_malicious": is_malicious,
            "malicious_sources": malicious_count,
            "sources_checked": sources_checked,
            "verdict_summary": " | ".join(verdict_parts) if verdict_parts else "Không phát hiện mối đe dọa",
            "details": results
        }

    def lookup_domain(self, domain: str) -> dict:
        """
        Lookup domain info: age, registrar, URLScan analysis.
        Newly registered domains (< 30 days) are high risk.
        """
        domain = domain.strip().lower()
        settings = get_settings()
        if settings.offline or not settings.network_enabled:
            return {
                "domain": domain,
                "is_suspicious": False,
                "age_days": None,
                "registrar": None,
                "urlscan_verdict": None
            }

        result = {
            "domain": domain,
            "is_suspicious": False,
            "age_days": None,
            "registrar": None,
            "urlscan_verdict": None
        }

        # URLScan.io domain lookup
        if self.urlscan_key:
            try:
                urlscan_res = self._urlscan_search_domain(domain)
                result["urlscan_verdict"] = urlscan_res
                if urlscan_res.get("malicious"):
                    result["is_suspicious"] = True
            except Exception as e:
                result["urlscan_error"] = str(e)

        from codebase.agents.explainable_agent import OFFICIAL_WHITELIST_DOMAINS
        for official in OFFICIAL_WHITELIST_DOMAINS:
            if domain == official or domain.endswith("." + official):
                result["is_suspicious"] = False
                result["is_official"] = True
                result["reason"] = f"Tên miền chính thức hợp pháp thuộc Whitelist (Official): {domain}"
                return result

        # Heuristic: suspicious TLDs + impersonation patterns
        suspicious_tlds = [".xyz", ".cc", ".tk", ".ml", ".ga", ".cf", ".info", ".top", ".pw"]
        impersonation = [
            "vietcombank-", "techcombank-", "agribank-", "vneid-",
            "bankingvn", "banking-vn", "chinhphu-", "canhsat-", "mofa-"
        ]
        if any(tld in domain for tld in suspicious_tlds):
            result["is_suspicious"] = True
            result["reason"] = f"TLD đáng ngờ trong domain: {domain}"
        if any(p in domain for p in impersonation):
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
        """Query VirusTotal URL scan API v3."""
        try:
            import base64
            # Encode URL to base64 (VT API v3 format)
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
                # URL not yet scanned → submit for scanning
                return self._submit_virustotal(url)
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
        """Query Google Safe Browsing API v4 for a list of URLs."""
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
        """Submit URL to URLScan.io for analysis and get verdict."""
        try:
            # Submit scan
            payload = json.dumps({"url": url, "visibility": "public"}).encode()
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
            if not uuid:
                return {"is_malicious": False, "error": "No scan UUID"}

            # Wait briefly then fetch result
            time.sleep(3)
            result_req = urllib.request.Request(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                headers={"API-Key": self.urlscan_key}
            )
            try:
                with urllib.request.urlopen(result_req, timeout=self.TIMEOUT) as resp2:
                    result_data = json.loads(resp2.read().decode())
                verdicts = result_data.get("verdicts", {}).get("overall", {})
                return {
                    "is_malicious": verdicts.get("malicious", False),
                    "score": verdicts.get("score", 0),
                    "categories": verdicts.get("categories", []),
                    "screenshot": result_data.get("task", {}).get("screenshotURL", ""),
                    "uuid": uuid
                }
            except Exception:
                # Result not ready yet — return pending
                return {
                    "is_malicious": False,
                    "status": "pending",
                    "uuid": uuid,
                    "result_url": f"https://urlscan.io/result/{uuid}/"
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
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc.lower().replace("www.", "")
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
