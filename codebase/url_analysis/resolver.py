from __future__ import annotations

import collections
import concurrent.futures
import copy
import functools
import http.client
import inspect
import ipaddress
import re
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

from codebase.config import get_settings
from codebase.url_analysis.normalize import load_url_lists
from codebase.url_analysis.parse import parse_url

# Linear regex for extracting meta refresh attributes without backtracking
RE_META_TAG = re.compile(r"<meta\b[^>]{1,2048}>", re.IGNORECASE)

# Disallowed host names and domain suffixes (SSRF protection)
FORBIDDEN_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".lan",
    ".home.arpa",
)
FORBIDDEN_HOST_NAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "local",
    "internal",
    "localdomain",
    "lan",
    "home.arpa",
}

# Special IPv6 networks with embedded IPv4 addresses
_NAT64_NET = ipaddress.IPv6Network("64:ff9b::/96")
_6TO4_NET = ipaddress.IPv6Network("2002::/16")

# Known non-global / private IPv4 networks
_DISALLOWED_V4_NETS = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("255.255.255.255/32"),
]


class _DaemonThreadPoolExecutor(concurrent.futures.ThreadPoolExecutor):
    """
    ThreadPoolExecutor whose worker threads are daemonized, ensuring they do not
    hang the Python process or pytest at interpreter shutdown if a mock task hangs.
    """

    def _adjust_thread_count(self):
        try:
            if self._idle_semaphore.acquire(timeout=0):
                return
            import weakref

            def weakref_cb(_, q=self._work_queue):
                q.put(None)

            num_threads = len(self._threads)
            if num_threads < self._max_workers:
                thread_name = "%s_%d" % (self._thread_name_prefix or self, num_threads)
                t = threading.Thread(
                    name=thread_name,
                    target=concurrent.futures.thread._worker,
                    args=(
                        weakref.ref(self, weakref_cb),
                        self._create_worker_context(),
                        self._work_queue,
                    ),
                    daemon=True,
                )
                t.start()
                self._threads.add(t)
        except Exception:
            super()._adjust_thread_count()


def _is_safe_ip(ip_str: str) -> tuple[bool, str]:
    """
    Validate that an IP address is global and public (not private, loopback,
    link-local, CGNAT, multicast, reserved, unspecified, or embedded private).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception as e:
        return False, f"invalid_ip:{e}"

    if isinstance(ip_obj, ipaddress.IPv6Address):
        # 1. Check IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        if ip_obj.ipv4_mapped is not None:
            v4 = ip_obj.ipv4_mapped
            if not v4.is_global or v4.is_private or v4.is_loopback:
                return False, "private_ip:ipv4_mapped"
            for net in _DISALLOWED_V4_NETS:
                if v4 in net:
                    return False, "private_ip:ipv4_mapped"

        # 2. Check NAT64 prefix (64:ff9b::/96)
        if ip_obj in _NAT64_NET:
            v4_int = int(ip_obj) & 0xFFFFFFFF
            v4 = ipaddress.IPv4Address(v4_int)
            if not v4.is_global or v4.is_private or v4.is_loopback:
                return False, "private_ip:nat64"
            for net in _DISALLOWED_V4_NETS:
                if v4 in net:
                    return False, "private_ip:nat64"

        # 3. Check 6to4 prefix (2002::/16)
        if ip_obj in _6TO4_NET:
            v4_int = (int(ip_obj) >> 80) & 0xFFFFFFFF
            v4 = ipaddress.IPv4Address(v4_int)
            if not v4.is_global or v4.is_private or v4.is_loopback:
                return False, "private_ip:6to4"
            for net in _DISALLOWED_V4_NETS:
                if v4 in net:
                    return False, "private_ip:6to4"

        # 4. Check general IPv6 properties
        if (
            not ip_obj.is_global
            or ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False, "private_ip"

    elif isinstance(ip_obj, ipaddress.IPv4Address):
        if (
            not ip_obj.is_global
            or ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False, "private_ip"

        for net in _DISALLOWED_V4_NETS:
            if ip_obj in net:
                return False, "private_ip"

    return True, ""


def is_public_destination(
    host: str,
    port: int,
    getaddrinfo: Callable = socket.getaddrinfo,
    timeout: float = 2.0,
) -> tuple[bool, str, list[str]]:
    """
    Resolve and validate that destination host:port is a public, global destination.
    Uses getaddrinfo inside a thread pool with strict timeout.

    Returns:
      (ok: bool, reason: str, ips: list[str])
    """
    clean_host = (host or "").strip().lower()
    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_host = clean_host[1:-1]

    # Reject forbidden names / suffixes
    bare_host = clean_host.rstrip(".")
    if bare_host in FORBIDDEN_HOST_NAMES or any(
        bare_host.endswith(suf) for suf in FORBIDDEN_HOST_SUFFIXES
    ):
        return False, "disallowed_host", []

    # Reject single label host (NetBIOS / local domain) if not IPv6
    if ":" not in clean_host and "." not in bare_host:
        return False, "disallowed_host:single_label", []

    # Check if host is already an IP literal
    try:
        ipaddress.ip_address(clean_host)
        is_literal = True
    except Exception:
        is_literal = False

    if is_literal:
        safe, reason = _is_safe_ip(clean_host)
        if not safe:
            return False, reason, [clean_host]
        return True, "", [clean_host]

    # Resolve all A and AAAA records in a thread with timeout
    executor = _DaemonThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(
            getaddrinfo,
            clean_host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
        addr_info_list = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        executor.shutdown(wait=False, cancel_futures=True)
        return False, "dns_timeout", []
    except Exception as e:
        executor.shutdown(wait=False, cancel_futures=True)
        return False, f"dns_error:{e}", []
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    if not addr_info_list:
        return False, "no_addresses_found", []

    # Extract distinct IP strings
    ips: list[str] = []
    for item in addr_info_list:
        if item and len(item) > 4 and item[4]:
            ip_cand = item[4][0]
            if ip_cand not in ips:
                ips.append(ip_cand)

    if not ips:
        return False, "no_addresses_found", []

    # Check ALL resolved IPs (fail closed if any IP is not global/private)
    for ip in ips:
        safe, reason = _is_safe_ip(ip)
        if not safe:
            return False, reason, ips

    return True, "", ips


def _extract_meta_refresh(html: str) -> str | None:
    """
    Extract refresh URL from <meta http-equiv="refresh" content="..."> linearly
    without exponential backtracking or nested quantifiers.
    """
    if not html:
        return None
    html_slice = html[:65536]
    html_low = html_slice.lower()

    start = 0
    while True:
        idx = html_low.find("<meta", start)
        if idx == -1:
            break
        end = html_low.find(">", idx)
        if end == -1:
            break
        if end - idx > 2048:
            start = idx + 5
            continue

        tag = html_slice[idx : end + 1]
        tag_low = html_low[idx : end + 1]
        if "http-equiv" in tag_low and "refresh" in tag_low:
            # Match content attribute linearly
            m = re.search(r'''content\s*=\s*["']?([^"'>]+)["']?''', tag, re.IGNORECASE)
            if m:
                content_val = m.group(1).strip()
                # Extract URL from content_val: e.g. "0; url=https://example.com"
                url_match = re.search(
                    r'''url\s*=\s*['"]?([^'";\s>]+)['"]?''',
                    content_val,
                    re.IGNORECASE,
                )
                if url_match:
                    return url_match.group(1).strip()
        start = idx + 5

    return None


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection pinned to an already-validated IP address."""

    def __init__(self, pinned_ip: str, port: int, timeout: float = 3.0):
        super().__init__(pinned_ip, port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an already-validated IP address with SNI and cert verification."""

    def __init__(
        self,
        pinned_ip: str,
        port: int,
        server_hostname: str,
        timeout: float = 3.0,
        context: ssl.SSLContext | None = None,
    ):
        if context is None:
            context = ssl.create_default_context()
        super().__init__(pinned_ip, port, timeout=timeout, context=context)
        self.pinned_ip = pinned_ip
        self.server_hostname = server_hostname

    def connect(self):
        sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(
            sock, server_hostname=self.server_hostname
        )


def default_transport(
    method: str,
    scheme: str,
    ip: str,
    port: int,
    host: str,
    path_and_query: str,
    headers: dict[str, str],
    timeout: float,
    max_body_bytes: int = 65536,
) -> tuple[int, dict[str, str], bytes]:
    """Default transport connecting directly to pinned IP without proxy bypass."""
    conn: http.client.HTTPConnection | None = None
    try:
        if scheme.lower() == "https":
            ctx = ssl.create_default_context()
            conn = PinnedHTTPSConnection(
                pinned_ip=ip,
                port=port,
                server_hostname=host,
                timeout=timeout,
                context=ctx,
            )
        else:
            conn = PinnedHTTPConnection(pinned_ip=ip, port=port, timeout=timeout)

        req_headers = dict(headers)
        if not any(k.lower() == "host" for k in req_headers):
            req_headers["Host"] = host if port in (80, 443) else f"{host}:{port}"

        conn.request(method, path_and_query, headers=req_headers)
        resp = conn.getresponse()
        status = resp.status
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}

        if method.upper() == "HEAD":
            body = b""
        else:
            body = resp.read(max_body_bytes)
        return status, resp_headers, body
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


@dataclass
class Hop:
    url: str
    status: int | None = None
    location: str | None = None
    ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "location": self.location,
            "ip": self.ip,
        }


@dataclass
class RedirectChain:
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    blocked_reason: str | None = None
    error: str | None = None
    elapsed_ms: float = 0.0
    from_cache: bool = False
    antibot: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hops": [h.to_dict() for h in self.hops],
            "final_url": self.final_url,
            "blocked_reason": self.blocked_reason,
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
            "from_cache": self.from_cache,
            "antibot": self.antibot,
        }


_SENTINEL_MODE = object()


class SafeRedirectResolver:
    """
    Safe HTTP/HTTPS redirect resolver with anti-SSRF protections, IP pinning
    against DNS rebinding, bounded execution budget, and LRU cache.
    """

    def __init__(
        self,
        mode: str | Any = _SENTINEL_MODE,
        max_hops: int = 5,
        per_hop_timeout: float = 3.0,
        total_budget: float = 6.0,
        max_body_bytes: int = 65536,
        transport: Any = None,
        getaddrinfo: Callable = socket.getaddrinfo,
        cache_ttl_s: int = 3600,
        cache_max: int = 512,
        ip_validator: Any = None,
        lists: dict[str, Any] | None = None,
    ):
        if mode is _SENTINEL_MODE or mode is None:
            cfg_mode = get_settings().redirect_mode
            self.mode = cfg_mode if cfg_mode else "shorteners"
        else:
            self.mode = str(mode).strip().lower()

        self.max_hops = max_hops
        self.per_hop_timeout = per_hop_timeout
        self.total_budget = total_budget
        self.max_body_bytes = max_body_bytes
        self.transport = transport
        self.getaddrinfo = getaddrinfo
        self.cache_ttl_s = cache_ttl_s
        self.cache_max = cache_max
        self.ip_validator = ip_validator
        self.lists = lists if lists is not None else load_url_lists()

        self._cache: collections.OrderedDict[str, tuple[RedirectChain, float]] = (
            collections.OrderedDict()
        )
        self._cache_lock = threading.Lock()

    def should_resolve(self, parsed_url: Any) -> bool:
        """
        Check if the parsed URL should be resolved under current mode:
          - 'off': never
          - 'shorteners': only when host/path is recognized as a shortener or redirector
          - 'all': any valid http(s) URL
        """
        if self.mode == "off":
            return False

        if isinstance(parsed_url, str):
            parsed = parse_url(parsed_url)
        else:
            parsed = parsed_url

        if not parsed or parsed.scheme not in ("http", "https"):
            return False

        if self.mode == "all":
            return True

        if self.mode == "shorteners":
            host = (parsed.effective_host or "").lower()
            reg_dom = (getattr(parsed, "registrable_domain", "") or "").lower()
            path = parsed.path or ""

            shorteners = {s.lower() for s in self.lists.get("shorteners", [])}
            if host in shorteners or reg_dom in shorteners:
                return True

            redirectors = self.lists.get("redirectors", {})
            for k in redirectors.keys():
                k_low = k.lower().strip()
                if "/" in k_low:
                    if f"{host}{path}".startswith(k_low):
                        return True
                else:
                    if host == k_low or host.endswith("." + k_low):
                        return True

            return False

        return False

    def _validate_destination(
        self, host: str, port: int, timeout: float
    ) -> tuple[bool, str, list[str]]:
        """Validate destination using ip_validator if injected, else is_public_destination."""
        if self.ip_validator is not None:
            try:
                sig = inspect.signature(self.ip_validator)
                param_count = len(sig.parameters)
            except Exception:
                param_count = 1

            if param_count >= 2:
                try:
                    if param_count == 2:
                        res = self.ip_validator(host, port)
                    elif param_count == 3:
                        res = self.ip_validator(host, port, self.getaddrinfo)
                    else:
                        res = self.ip_validator(host, port, self.getaddrinfo, timeout)
                    if isinstance(res, tuple):
                        return res
                    if isinstance(res, bool):
                        return res, "" if res else "ip_rejected", [host]
                except Exception as e:
                    return False, f"validator_error:{e}", []
            else:
                ok, reason, ips = is_public_destination(
                    host, port, getaddrinfo=self.getaddrinfo, timeout=timeout
                )
                if not ok and ips:
                    all_allowed = True
                    for ip in ips:
                        try:
                            if not self.ip_validator(ip):
                                all_allowed = False
                                break
                        except Exception:
                            all_allowed = False
                            break
                    if all_allowed:
                        return True, "", ips
                elif not ok and not ips:
                    try:
                        if self.ip_validator(host):
                            return True, "", [host]
                    except Exception:
                        pass
                return ok, reason, ips

        return is_public_destination(
            host, port, getaddrinfo=self.getaddrinfo, timeout=timeout
        )

    def resolve(self, url: str) -> RedirectChain:
        """
        Safely resolve redirects for the given URL, strictly adhering to anti-SSRF,
        IP pinning, budget limits, and exception safety rules. Never raises outside.
        """
        try:
            return self._resolve_internal(url)
        except Exception as e:
            return RedirectChain(
                hops=[],
                final_url=None,
                blocked_reason=None,
                error=str(e),
                elapsed_ms=0.0,
                from_cache=False,
                antibot=None,
            )

    def _resolve_internal(self, url: str) -> RedirectChain:
        t_start = time.monotonic()

        # Rule 9: Check network settings
        settings = get_settings()
        if not settings.network_enabled or settings.offline:
            return RedirectChain(
                hops=[],
                final_url=None,
                blocked_reason="network_disabled",
                error=None,
                elapsed_ms=0.0,
                from_cache=False,
                antibot=None,
            )

        # Parse initial URL
        parsed = parse_url(url)

        # Rule 1: Check initial scheme
        if parsed.scheme not in ("http", "https"):
            return RedirectChain(
                hops=[],
                final_url=None,
                blocked_reason=f"disallowed_scheme:{parsed.scheme or 'none'}",
                error=None,
                elapsed_ms=0.0,
                from_cache=False,
                antibot=None,
            )

        # Check mode and eligibility
        if self.mode == "off":
            return RedirectChain(
                hops=[],
                final_url=None,
                blocked_reason="mode_off",
                error=None,
                elapsed_ms=0.0,
                from_cache=False,
                antibot=None,
            )

        if not self.should_resolve(parsed):
            return RedirectChain(
                hops=[],
                final_url=None,
                blocked_reason="not_a_shortener",
                error=None,
                elapsed_ms=0.0,
                from_cache=False,
                antibot=None,
            )

        # Cache check
        norm_key = url.strip()
        with self._cache_lock:
            if norm_key in self._cache:
                cached_chain, expires_at = self._cache[norm_key]
                if time.monotonic() < expires_at:
                    self._cache.move_to_end(norm_key)
                    res = copy.deepcopy(cached_chain)
                    res.from_cache = True
                    return res
                else:
                    del self._cache[norm_key]

        hops: list[Hop] = []
        seen_urls: set[str] = set()
        current_url = url
        blocked_reason: str | None = None
        error: str | None = None
        final_url: str | None = None

        while True:
            # Check hops limit
            if len(hops) >= self.max_hops:
                error = "too_many_hops"
                break

            # Budget check
            remaining_budget = self.total_budget - (time.monotonic() - t_start)
            if remaining_budget <= 0:
                error = "budget_exceeded"
                break

            # Loop detection
            norm_curr = current_url.strip()
            if norm_curr in seen_urls:
                error = "redirect_loop"
                break
            seen_urls.add(norm_curr)

            # Parse and validate current URL
            p = parse_url(current_url)

            # Rule 1: Scheme
            if p.scheme not in ("http", "https"):
                blocked_reason = f"disallowed_scheme:{p.scheme or 'none'}"
                break

            # Rule 1: Userinfo
            if p.userinfo:
                blocked_reason = "userinfo_forbidden"
                break

            # Rule 1: Port
            port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
            if self.ip_validator is None and port not in (80, 443):
                blocked_reason = f"disallowed_port:{port}"
                break

            # Rule 2 & 3: Host
            host = (p.effective_host or "").lower()
            if not host:
                blocked_reason = "disallowed_host:empty"
                break

            bare_host = host.rstrip(".")
            if bare_host in FORBIDDEN_HOST_NAMES or any(
                bare_host.endswith(suf) for suf in FORBIDDEN_HOST_SUFFIXES
            ):
                blocked_reason = "disallowed_host"
                break

            if not bare_host.startswith("[") and "." not in bare_host:
                blocked_reason = "disallowed_host:single_label"
                break

            # Rule 4: Destination & IP validation
            dns_timeout = min(self.per_hop_timeout, remaining_budget)
            ok, reason, ips = self._validate_destination(
                bare_host, port, timeout=dns_timeout
            )
            if not ok:
                if "timeout" in reason:
                    if time.monotonic() - t_start >= self.total_budget:
                        error = "budget_exceeded"
                    else:
                        error = "dns_timeout"
                elif "private" in reason or "loopback" in reason:
                    blocked_reason = f"private_destination:{reason}"
                else:
                    blocked_reason = f"destination_blocked:{reason}"
                break

            if not ips:
                blocked_reason = "destination_blocked:no_ips"
                break

            # Rule 5: Pin the IP address
            pinned_ip = ips[0]

            # Path and query
            path_and_query = p.path or "/"
            if p.query:
                path_and_query += "?" + p.query

            host_hdr = host if port in (80, 443) else f"{host}:{port}"
            headers = {
                "Host": host_hdr,
                "User-Agent": "SafeGuardAI-LinkChecker/1.0",
                "Accept-Encoding": "identity",
            }

            transport_fn = self.transport or default_transport

            remaining_budget = self.total_budget - (time.monotonic() - t_start)
            if remaining_budget <= 0:
                error = "budget_exceeded"
                break
            timeout = min(self.per_hop_timeout, remaining_budget)

            # Rule 6: Request HEAD first
            try:
                status, resp_headers, body = transport_fn(
                    "HEAD",
                    p.scheme,
                    pinned_ip,
                    port,
                    host,
                    path_and_query,
                    headers,
                    timeout,
                )
            except Exception as e:
                if isinstance(e, (TimeoutError, socket.timeout)) or "timeout" in str(e).lower():
                    if time.monotonic() - t_start >= self.total_budget:
                        error = "budget_exceeded"
                    else:
                        error = "request_timeout"
                else:
                    error = f"transport_error:{e}"
                break

            # If HEAD returns 405/501/403, fallback to GET
            if status in (405, 501, 403):
                remaining_budget = self.total_budget - (time.monotonic() - t_start)
                if remaining_budget <= 0:
                    error = "budget_exceeded"
                    break
                timeout = min(self.per_hop_timeout, remaining_budget)
                try:
                    status, resp_headers, body = transport_fn(
                        "GET",
                        p.scheme,
                        pinned_ip,
                        port,
                        host,
                        path_and_query,
                        headers,
                        timeout,
                    )
                except Exception as e:
                    if isinstance(e, (TimeoutError, socket.timeout)) or "timeout" in str(e).lower():
                        if time.monotonic() - t_start >= self.total_budget:
                            error = "budget_exceeded"
                        else:
                            error = "request_timeout"
                    else:
                        error = f"transport_error:{e}"
                    break

            # Truncate body if larger than max_body_bytes
            if body and len(body) > self.max_body_bytes:
                body = body[: self.max_body_bytes]

            resp_headers_lower = {str(k).lower(): str(v) for k, v in resp_headers.items()}
            raw_location = resp_headers_lower.get("location")

            # Check meta refresh if no HTTP redirect Location
            meta_refresh_url = None
            if not raw_location or status not in (301, 302, 303, 307, 308):
                if body:
                    try:
                        body_str = body.decode("utf-8", errors="replace")
                    except Exception:
                        body_str = str(body)
                    meta_refresh_url = _extract_meta_refresh(body_str)

            redirect_target = raw_location if (status in (301, 302, 303, 307, 308) and raw_location) else meta_refresh_url

            if redirect_target:
                if len(redirect_target) > 2048:
                    error = "location_too_long"
                    hops.append(
                        Hop(
                            url=current_url,
                            status=status,
                            location=redirect_target,
                            ip=pinned_ip,
                        )
                    )
                    break

                next_url = urllib.parse.urljoin(current_url, redirect_target)
                hops.append(
                    Hop(
                        url=current_url,
                        status=status,
                        location=redirect_target,
                        ip=pinned_ip,
                    )
                )

                if len(hops) >= self.max_hops:
                    error = "too_many_hops"
                    break

                current_url = next_url
                continue
            else:
                # Final hop reached
                hops.append(
                    Hop(
                        url=current_url,
                        status=status,
                        location=None,
                        ip=pinned_ip,
                    )
                )
                final_url = current_url
                break

        elapsed_ms = (time.monotonic() - t_start) * 1000.0

        chain = RedirectChain(
            hops=hops,
            final_url=final_url,
            blocked_reason=blocked_reason,
            error=error,
            elapsed_ms=elapsed_ms,
            from_cache=False,
            antibot=None,
        )

        # Cache entry
        if blocked_reason is not None:
            ttl = min(60, self.cache_ttl_s)
        elif error is None:
            ttl = self.cache_ttl_s
        else:
            ttl = 0

        if ttl > 0:
            with self._cache_lock:
                if len(self._cache) >= self.cache_max:
                    self._cache.popitem(last=False)
                self._cache[norm_key] = (copy.deepcopy(chain), time.monotonic() + ttl)

        return chain
