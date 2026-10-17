"""
Passive Domain Intelligence Module for SafeGuardAI.

Collects passive security signals without loading web pages (bypassing bot-detection/cloaking):
  1. Domain age via RDAP (rdap.org)
  2. Certificate Transparency first-seen via crt.sh
  3. TLS certificate handshake and verification (without HTTP data)
  4. DNS resolution status (NXDOMAIN detection)

PRIVACY AND SECURITY GUARANTEES:
- PRIVACY: NEVER sends full URLs, paths, or query parameters to external services.
  ONLY the registrable domain (or effective host for TLS/DNS) is ever queried.
- SSRF PROTECTION: All outbound queries go through SafeRedirectResolver or probe_tls_certificate
  with pinned public IPs, bounded DNS pool, and deadline budgets.
- OFFLINE-FIRST: Zero network calls when SAFEGUARD_OFFLINE=1 or network_enabled=False.
- FAIL-SAFE: All errors are caught safely and return None without crashing the caller.
"""

from __future__ import annotations

import collections
import concurrent.futures
from datetime import datetime, timezone
import json
import re
import socket
import threading
import time
from typing import Any, Callable

from codebase.config import get_settings
from codebase.url_analysis.models import UrlFinding
from codebase.url_analysis.resolver import (
    SafeRedirectResolver,
    _DNS_POOL,
    is_public_destination,
    probe_tls_certificate,
)

# Linear domain validation regex (max 63 chars per LDH label, linear)
_LABEL_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_valid_domain(domain: str) -> bool:
    """
    Validate that a domain is well-formed using linear regex.
    Bounded length <= 253, at least 1 dot, each label 1-63 LDH/punycode chars.
    """
    if not domain or not isinstance(domain, str):
        return False
    d = domain.strip().lower().rstrip(".")
    if len(d) > 253 or len(d) < 3 or "." not in d:
        return False
    labels = d.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not _LABEL_REGEX.match(label):
            return False
    return True


def _parse_iso_date(date_str: str) -> datetime | None:
    """Safely parse various ISO date strings into a UTC datetime."""
    if not date_str or not isinstance(date_str, str):
        return None
    s = date_str.strip()
    if len(s) > 64:
        return None

    # Replace trailing 'Z' with '+00:00' for broad compatibility
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        # Fallback for common space-separated format
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                continue
    return None


class PassiveIntel:
    """
    Passive intelligence aggregator for domain age, Certificate Transparency,
    TLS certificate probe, and DNS status.
    Thread-safe, LRU-cached with TTL, bounded budgets.
    """

    def __init__(
        self,
        fetch: Callable | None = None,
        probe: Callable | None = None,
        dns: Callable | None = None,
        cache_ttl_s: int = 21600,  # 6 hours
        cache_max: int = 512,
        clock: Callable[[], float] = time.time,
    ):
        self._fetch_fn = fetch
        self._probe_fn = probe
        self._dns_fn = dns
        self.cache_ttl_s = cache_ttl_s
        self.cache_max = cache_max
        self.clock = clock

        self._cache: collections.OrderedDict[str, tuple[Any, float]] = collections.OrderedDict()
        self._cache_lock = threading.Lock()
        self._default_resolver: SafeRedirectResolver | None = None

    def _get_fetch(self) -> Callable:
        if self._fetch_fn is not None:
            return self._fetch_fn
        if self._default_resolver is None:
            self._default_resolver = SafeRedirectResolver()
        return self._default_resolver.fetch

    def _get_probe(self) -> Callable:
        if self._probe_fn is not None:
            return self._probe_fn
        return probe_tls_certificate

    def _get_from_cache(self, key: str) -> tuple[bool, Any]:
        with self._cache_lock:
            if key in self._cache:
                val, expires_at = self._cache[key]
                if self.clock() < expires_at:
                    self._cache.move_to_end(key)
                    return True, val
                else:
                    del self._cache[key]
        return False, None

    def _put_into_cache(self, key: str, val: Any) -> None:
        if self.cache_ttl_s <= 0:
            return
        with self._cache_lock:
            if len(self._cache) >= self.cache_max:
                self._cache.popitem(last=False)
            self._cache[key] = (val, self.clock() + self.cache_ttl_s)

    def domain_age(
        self,
        registrable: str,
        *,
        recorder: Any = None,
        timeout: float = 3.0,
    ) -> dict[str, Any] | None:
        """
        Query domain registration age via RDAP (https://rdap.org/domain/{domain}).
        PRIVACY: Only queries registrable domain. Never sends user URL.

        Returns:
          {"created": ISO date str | None, "age_days": int | None} or None on error/404/offline.
        """
        settings = get_settings()
        if not settings.network_enabled or settings.offline:
            return None

        if not _is_valid_domain(registrable):
            return None

        reg = registrable.strip().lower().rstrip(".")
        cache_key = f"age:{reg}"
        found, cached = self._get_from_cache(cache_key)
        if found:
            return cached

        fetch = self._get_fetch()
        url = f"https://rdap.org/domain/{reg}"

        rec_idx = None
        if recorder is not None:
            rec_idx = recorder.record_request("rdap_lookup", reg)

        try:
            res = fetch(url, allow_hosts={"rdap.org"}, timeout=timeout)
        except Exception:
            if rec_idx is not None:
                recorder.update_status(rec_idx, "error")
            return None

        if res is None:
            if rec_idx is not None:
                recorder.update_status(rec_idx, "error")
            return None

        if rec_idx is not None:
            recorder.update_status(rec_idx, "ok")

        status, headers, body_bytes = res
        if status == 404:
            self._put_into_cache(cache_key, None)
            return None

        if status != 200 or not body_bytes:
            return None

        try:
            body_text = body_bytes.decode("utf-8", errors="replace")
            data = json.loads(body_text)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        events = data.get("events")
        if not isinstance(events, list):
            res_val = {"created": None, "age_days": None}
            self._put_into_cache(cache_key, res_val)
            return res_val

        event_date_str = None
        for ev in events:
            if isinstance(ev, dict) and ev.get("eventAction") == "registration":
                event_date_str = ev.get("eventDate")
                break

        if not event_date_str:
            res_val = {"created": None, "age_days": None}
            self._put_into_cache(cache_key, res_val)
            return res_val

        dt = _parse_iso_date(str(event_date_str))
        if dt is None:
            res_val = {"created": None, "age_days": None}
            self._put_into_cache(cache_key, res_val)
            return res_val

        # Sanity check unreasonable years (e.g. 1900 or 3000)
        now_dt = datetime.now(timezone.utc)
        if dt.year < 1985 or dt.year > now_dt.year + 1:
            res_val = {"created": None, "age_days": None}
            self._put_into_cache(cache_key, res_val)
            return res_val

        age_days = max(0, int((now_dt - dt).total_seconds() // 86400))
        res_val = {
            "created": dt.isoformat(),
            "age_days": age_days,
        }
        self._put_into_cache(cache_key, res_val)
        return res_val

    def ct_first_seen(
        self,
        registrable: str,
        *,
        recorder: Any = None,
        timeout: float = 3.0,
    ) -> dict[str, Any] | None:
        """
        Query Certificate Transparency for earliest certificate via crt.sh JSON API.
        PRIVACY: Only queries registrable domain. Never sends user URL.

        Returns:
          {"first_seen": ISO date str | None, "cert_count": int} or None on error/timeout/offline.
        """
        settings = get_settings()
        if not settings.network_enabled or settings.offline:
            return None

        if not _is_valid_domain(registrable):
            return None

        reg = registrable.strip().lower().rstrip(".")
        cache_key = f"ct:{reg}"
        found, cached = self._get_from_cache(cache_key)
        if found:
            return cached

        fetch = self._get_fetch()
        url = f"https://crt.sh/?q={reg}&output=json"

        rec_idx = None
        if recorder is not None:
            rec_idx = recorder.record_request("crtsh_lookup", reg)

        try:
            res = fetch(url, allow_hosts={"crt.sh"}, max_bytes=262144, timeout=timeout)
        except Exception:
            if rec_idx is not None:
                recorder.update_status(rec_idx, "error")
            return None

        if res is None:
            if rec_idx is not None:
                recorder.update_status(rec_idx, "error")
            return None

        if rec_idx is not None:
            recorder.update_status(rec_idx, "ok")

        status, headers, body_bytes = res
        if status != 200 or not body_bytes:
            return None

        # Ignore HTML error pages (e.g. 502/504 Bad Gateway from crt.sh)
        body_start = body_bytes[:100].strip().lower()
        if body_start.startswith(b"<") or b"<html" in body_start:
            return None

        try:
            body_text = body_bytes.decode("utf-8", errors="replace")
            items = json.loads(body_text)
        except Exception:
            # S2: Handle truncated JSON by parsing up to the last complete element
            last_brace = body_text.rfind("}")
            if last_brace != -1:
                try:
                    items = json.loads(body_text[:last_brace + 1] + "]")
                except Exception:
                    return None
            else:
                return None

        if not isinstance(items, list):
            return None

        min_dt: datetime | None = None
        cert_count = 0

        for item in items:
            if not isinstance(item, dict):
                continue
            cand_str = item.get("entry_timestamp") or item.get("not_before")
            if not cand_str:
                continue
            cert_count += 1
            dt = _parse_iso_date(str(cand_str))
            if dt:
                now_dt = datetime.now(timezone.utc)
                if 1990 <= dt.year <= now_dt.year + 1:
                    if min_dt is None or dt < min_dt:
                        min_dt = dt

        res_val = {
            "first_seen": min_dt.isoformat() if min_dt else None,
            "cert_count": cert_count,
        }
        self._put_into_cache(cache_key, res_val)
        return res_val

    def tls(
        self,
        host: str,
        *,
        recorder: Any = None,
        timeout: float = 3.0,
    ) -> dict[str, Any] | None:
        """
        Probe TLS certificate of host on port 443 with verification.
        Does not send HTTP data.
        P3: Disabled by default unless Settings.passive_tls is True.

        Returns dict or None.
        """
        settings = get_settings()
        if not settings.network_enabled or settings.offline or not settings.passive_tls:
            return None

        clean_host = (host or "").strip().lower()
        if not clean_host:
            return None

        cache_key = f"tls:{clean_host}"
        found, cached = self._get_from_cache(cache_key)
        if found:
            return cached

        rec_idx = None
        if recorder is not None:
            rec_idx = recorder.record_request("tls_probe", clean_host)

        probe = self._get_probe()
        try:
            res = probe(clean_host, timeout=timeout)
            if rec_idx is not None:
                recorder.update_status(rec_idx, "ok" if res is not None else "error")
        except Exception as e:
            if rec_idx is not None:
                if "timeout" in str(e).lower() or isinstance(e, (TimeoutError, socket.timeout)):
                    recorder.update_status(rec_idx, "timeout")
                else:
                    recorder.update_status(rec_idx, "error")
            res = None

        if res is not None:
            self._put_into_cache(cache_key, res)
        return res

    def dns_status(
        self,
        host: str,
        *,
        recorder: Any = None,
        timeout: float = 3.0,
    ) -> str:
        """
        Check DNS resolution status using the shared bounded DNS pool.

        Returns:
          'ok' | 'nxdomain' | 'unknown'
        """
        settings = get_settings()
        if not settings.network_enabled or settings.offline:
            return "unknown"

        clean_host = (host or "").strip().lower().rstrip(".")
        if not clean_host:
            return "unknown"

        # P3: dns_status không phân biệt tên nội bộ với NXDOMAIN ra ngoài (tên nội bộ/.local/không có dấu chấm => 'unknown')
        if (
            "." not in clean_host
            or clean_host.startswith("[")
            or clean_host in ("localhost", "metadata", "local", "internal", "localdomain", "lan", "home.arpa")
            or any(clean_host.endswith(suf) for suf in (".local", ".internal", ".localhost", ".lan", ".home.arpa", ".localdomain"))
        ):
            return "unknown"

        cache_key = f"dns:{clean_host}"
        found, cached = self._get_from_cache(cache_key)
        if found:
            return cached

        rec_idx = None
        if recorder is not None:
            rec_idx = recorder.record_request("dns_lookup", clean_host)

        if self._dns_fn is not None:
            try:
                res = self._dns_fn(clean_host)
                self._put_into_cache(cache_key, res)
                if rec_idx is not None:
                    recorder.update_status(rec_idx, "ok" if res in ("ok", "nxdomain") else "error")
                return res
            except Exception as e:
                if rec_idx is not None:
                    if "timeout" in str(e).lower() or isinstance(e, (TimeoutError, socket.timeout)):
                        recorder.update_status(rec_idx, "timeout")
                    else:
                        recorder.update_status(rec_idx, "error")
                return "unknown"

        # Check destination via shared bounded pool using socket.getaddrinfo
        try:
            addr_info_list = _DNS_POOL.resolve(
                socket.getaddrinfo,
                (clean_host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM),
                {},
                timeout=timeout,
            )
            if addr_info_list:
                status = "ok"
            else:
                status = "unknown"
            if rec_idx is not None:
                recorder.update_status(rec_idx, "ok" if status == "ok" else "error")
        except socket.gaierror as e:
            # Genuine NXDOMAIN / host not found
            err_str = str(e).lower()
            errno = getattr(e, "errno", None)
            if (
                errno in (getattr(socket, "EAI_NONAME", -2), getattr(socket, "EAI_NODATA", -5), 11001)
                or "11001" in err_str
                or "name or service not known" in err_str
                or "nodename nor servname" in err_str
                or "no address associated with hostname" in err_str
            ):
                status = "nxdomain"
            else:
                status = "unknown"
            if rec_idx is not None:
                recorder.update_status(rec_idx, "ok" if status == "nxdomain" else "error")
        except Exception as e:
            status = "unknown"
            if rec_idx is not None:
                if "timeout" in str(e).lower() or isinstance(e, (TimeoutError, socket.timeout)):
                    recorder.update_status(rec_idx, "timeout")
                else:
                    recorder.update_status(rec_idx, "error")

        self._put_into_cache(cache_key, status)
        return status

    def analyze(
        self,
        finding: UrlFinding,
        *,
        deadline_s: float = 5.0,
        recorder: Any = None,
    ) -> dict[str, Any] | None:
        """
        Aggregate passive intelligence across all 4 sources:
          - domain_age (RDAP)
          - ct_first_seen (crt.sh)
          - tls (probe)
          - dns_status (shared DNS)

        Runs each with a 3.0s timeout within a 5.0s overall budget.
        Thread-safe, safely absorbs all exceptions, returning None on error.
        If offline or network disabled, makes 0 network calls and returns None.
        """
        settings = get_settings()
        if not settings.network_enabled or settings.offline:
            return None

        host = (finding.effective_host or "").strip().lower().rstrip(".")
        registrable = (finding.registrable_domain or "").strip().lower().rstrip(".")

        if not host and not registrable:
            return None

        t_start = time.monotonic()
        total_budget = min(deadline_s, 5.0)
        overall_deadline = t_start + total_budget

        results: dict[str, Any] = {
            "domain_age": None,
            "ct": None,
            "tls": None,
            "dns_status": "unknown",
        }

        # Check if registrable domain is valid to query
        can_query_domain = _is_valid_domain(registrable)

        # Worker tasks
        def run_domain_age():
            if not can_query_domain:
                return None
            rem = max(0.1, overall_deadline - time.monotonic())
            return self.domain_age(registrable, recorder=recorder, timeout=min(3.0, rem))

        def run_ct():
            if not can_query_domain:
                return None
            rem = max(0.1, overall_deadline - time.monotonic())
            return self.ct_first_seen(registrable, recorder=recorder, timeout=min(3.0, rem))

        def run_tls():
            if not host:
                return None
            rem = max(0.1, overall_deadline - time.monotonic())
            return self.tls(host, recorder=recorder, timeout=min(3.0, rem))

        def run_dns():
            if not host:
                return "unknown"
            rem = max(0.1, overall_deadline - time.monotonic())
            return self.dns_status(host, recorder=recorder, timeout=min(3.0, rem))

        tasks = {
            "domain_age": run_domain_age,
            "ct": run_ct,
            "tls": run_tls,
            "dns_status": run_dns,
        }

        # Run tasks concurrently with thread pool, bounded by deadline
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        try:
            future_to_key = {executor.submit(fn): key for key, fn in tasks.items()}
            rem = max(0.001, overall_deadline - time.monotonic())
            try:
                for future in concurrent.futures.as_completed(future_to_key, timeout=rem):
                    key = future_to_key[future]
                    try:
                        results[key] = future.result()
                    except Exception:
                        results[key] = "unknown" if key == "dns_status" else None
            except concurrent.futures.TimeoutError:
                pass
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        return results
