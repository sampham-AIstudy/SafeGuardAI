from __future__ import annotations

import collections
import copy
import inspect
import ipaddress
import queue
import re
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from codebase.config import get_settings
from codebase.url_analysis.antibot import classify_response
from codebase.url_analysis.normalize import load_url_lists
from codebase.url_analysis.parse import parse_url

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


class _DNSLookupPool:
    """
    Module-level bounded DNS worker pool with up to 8 daemon threads,
    limiting pending waiting lookups to 16 with a semaphore (S1).
    """

    def __init__(self, max_workers: int = 8, max_pending: int = 16):
        self.max_workers = max_workers
        self.max_pending = max_pending
        self.pending_semaphore = threading.Semaphore(max_pending)
        self.work_queue: queue.Queue = queue.Queue()
        self.workers: list[threading.Thread] = []
        self.lock = threading.Lock()

    def _ensure_worker(self):
        with self.lock:
            self.workers = [w for w in self.workers if w.is_alive()]
            if len(self.workers) < self.max_workers:
                w = threading.Thread(target=self._worker_loop, daemon=True)
                w.start()
                self.workers.append(w)

    def _worker_loop(self):
        while True:
            try:
                task = self.work_queue.get()
            except Exception:
                break
            if task is None:
                break
            fn, args, kwargs, result_event, result_box, exc_box, cancelled_box = task
            try:
                if not cancelled_box[0]:
                    res = fn(*args, **kwargs)
                    result_box.append(res)
            except Exception as e:
                if not cancelled_box[0]:
                    exc_box.append(e)
            finally:
                result_event.set()
                self.pending_semaphore.release()
                self.work_queue.task_done()

    def resolve(self, fn: Callable, args: tuple, kwargs: dict, timeout: float) -> list:
        # Limit pending lookups with semaphore (fail-closed if full)
        acquired = self.pending_semaphore.acquire(blocking=False)
        if not acquired:
            raise RuntimeError("dns_busy")

        result_event = threading.Event()
        result_box: list = []
        exc_box: list[Exception] = []
        cancelled_box = [False]
        task = (fn, args, kwargs, result_event, result_box, exc_box, cancelled_box)

        self._ensure_worker()
        self.work_queue.put(task)

        finished = result_event.wait(timeout=timeout)
        if not finished:
            cancelled_box[0] = True
            raise TimeoutError("dns_timeout")

        if exc_box:
            raise exc_box[0]
        if result_box:
            return result_box[0]
        return []


_DNS_POOL = _DNSLookupPool()


def _is_safe_ip(ip_str: str) -> tuple[bool, str]:
    """
    Validate that an IP address is global and public (not private, loopback,
    link-local, CGNAT, multicast, reserved, unspecified, or embedded private).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except Exception as e:
        return False, f"invalid_ip:{type(e).__name__}"

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
    getaddrinfo: Callable | None = None,
    timeout: float = 2.0,
    *,
    _test_ip_filter: Callable[[str], bool] | None = None,
) -> tuple[bool, str, list[str]]:
    """
    Resolve and validate that destination host:port is a public, global destination.
    Uses module-level bounded worker pool with timeout.

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
            if _test_ip_filter is not None and _test_ip_filter(clean_host):
                return True, "", [clean_host]
            return False, reason, [clean_host]
        return True, "", [clean_host]

    # Resolve all A and AAAA records in bounded worker pool with timeout
    gai = getaddrinfo if getaddrinfo is not None else socket.getaddrinfo
    try:
        addr_info_list = _DNS_POOL.resolve(
            gai,
            (clean_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM),
            {},
            timeout=timeout,
        )
    except TimeoutError:
        return False, "dns_timeout", []
    except RuntimeError as e:
        if "dns_busy" in str(e):
            return False, "dns_busy", []
        return False, "dns_error", []
    except Exception:
        return False, "dns_error", []

    if not addr_info_list:
        return False, "no_addresses_found", []

    # Extract distinct IP strings
    ips: list[str] = []
    for item in addr_info_list:
        if item and len(item) > 4 and item[4]:
            ip_cand = str(item[4][0])
            if ip_cand not in ips:
                ips.append(ip_cand)

    if not ips:
        return False, "no_addresses_found", []

    # Check ALL resolved IPs (fail closed if any IP is not global/private)
    for ip in ips:
        safe, reason = _is_safe_ip(ip)
        if not safe:
            if _test_ip_filter is not None and _test_ip_filter(ip):
                continue
            return False, reason, ips

    return True, "", ips


def _extract_meta_refresh(html: str) -> str | None:
    """
    Extract refresh URL from <meta http-equiv="refresh" content="..."> linearly
    without exponential backtracking or nested quantifiers (S4).
    Supports url='...', url="...", URL=..., and content without semicolon.
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
            # Match content attribute linearly supporting double, single, or unquoted values
            m = re.search(
                r'''content\s*=\s*"([^"]{1,1024})"|content\s*=\s*'([^']{1,1024})'|content\s*=\s*([^\s>]{1,1024})''',
                tag,
                re.IGNORECASE,
            )
            if m:
                content_val = (m.group(1) or m.group(2) or m.group(3) or "").strip()
                # Parse URL from content_val linearly supporting url="...", url='...', url=...
                url_m = re.search(
                    r'''url\s*=\s*"([^"]{1,1024})"|url\s*=\s*'([^']{1,1024})'|url\s*=\s*([^\s;>]{1,1024})''',
                    content_val,
                    re.IGNORECASE,
                )
                if url_m:
                    raw_u = (url_m.group(1) or url_m.group(2) or url_m.group(3) or "").strip()
                    raw_u = raw_u.strip("'\"")
                    if raw_u:
                        return raw_u
        start = idx + 5

    return None


def _normalize_location(raw_loc: str, current_url: str) -> tuple[str, bool]:
    """
    WHATWG-compliant normalization for redirect Location header (S2):
    - Strips C0 control characters and spaces from edges.
    - Removes tab, CR, LF.
    - Replaces backslashes with slashes for http/https.
    - Normalizes leading '//+' to '//' (network-path).
    - Resolves relative/absolute target without RFC 3986 urljoin cloaking.
    - Returns (normalized_url, backslash_confusion_detected).
    """
    curr_p = parse_url(current_url)
    curr_scheme = (curr_p.scheme or "http").lower()
    curr_host = curr_p.effective_host or ""
    curr_port = curr_p.port
    curr_path = curr_p.path or "/"

    # Strip C0 control characters (\x00-\x1f, \x7f) and spaces
    loc = raw_loc.strip(
        " \t\r\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f"
    )
    # Remove tab, CR, LF
    loc = re.sub(r"[\r\n\t]", "", loc)

    had_backslash = "\\" in loc
    if curr_scheme in ("http", "https"):
        loc = loc.replace("\\", "/")

    # Check for network-path reference (//+)
    if loc.startswith("//"):
        loc = re.sub(r"^/+", "//", loc)
        candidate_url = f"{curr_scheme}:{loc}"
    else:
        cand_p = parse_url(loc)
        if cand_p.scheme:
            candidate_url = loc
        elif loc.startswith("/"):
            port_part = (
                f":{curr_port}"
                if curr_port and curr_port not in (80, 443)
                else ""
            )
            candidate_url = f"{curr_scheme}://{curr_host}{port_part}{loc}"
        elif loc.startswith("?"):
            port_part = (
                f":{curr_port}"
                if curr_port and curr_port not in (80, 443)
                else ""
            )
            candidate_url = f"{curr_scheme}://{curr_host}{port_part}{curr_path}{loc}"
        elif loc.startswith("#"):
            port_part = (
                f":{curr_port}"
                if curr_port and curr_port not in (80, 443)
                else ""
            )
            candidate_url = f"{curr_scheme}://{curr_host}{port_part}{curr_path}{loc}"
        else:
            base_dir = curr_path.rsplit("/", 1)[0] + "/"
            port_part = (
                f":{curr_port}"
                if curr_port and curr_port not in (80, 443)
                else ""
            )
            candidate_url = f"{curr_scheme}://{curr_host}{port_part}{base_dir}{loc}"

    # Detect backslash confusion
    backslash_confusion = False
    if had_backslash:
        try:
            rfc_joined = urllib.parse.urljoin(current_url, raw_loc)
            rfc_p = parse_url(rfc_joined)
            cand_p = parse_url(candidate_url)
            if cand_p.effective_host != rfc_p.effective_host:
                backslash_confusion = True
        except Exception:
            backslash_confusion = True

    return candidate_url, backslash_confusion


def _sanitize_hop_str(val: str | None) -> str | None:
    """Sanitize hop URL or location to <= 512 chars and strip control characters (S7)."""
    if val is None:
        return None
    cleaned = "".join(c for c in val if ord(c) >= 32 and ord(c) != 127)
    if len(cleaned) > 512:
        cleaned = cleaned[:512]
    return cleaned


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
    deadline: float | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """
    Default HTTP/1.1 transport connecting directly to pinned IP without proxy bypass (B1).
    Strictly bounds every socket read/write/handshake to the overall deadline.
    Status line <= 4KB, headers <= 16KB and <= 100 lines, max 3 consecutive 1xx responses,
    body bounded by max_body_bytes.
    """
    if deadline is None:
        deadline = time.monotonic() + timeout

    def _sock_timeout() -> float:
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("budget_exceeded")
        return max(0.001, min(timeout, rem))

    sock: socket.socket | None = None
    try:
        cur_to = _sock_timeout()
        is_ipv6 = ":" in ip and not ip.startswith("[")
        family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(cur_to)
        sock.connect((ip, port))

        # TLS handshake
        if scheme.lower() == "https":
            sock.settimeout(_sock_timeout())
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            sock = ctx.wrap_socket(sock, server_hostname=host)

        # Build HTTP request
        req_headers = dict(headers)
        if not any(k.lower() == "host" for k in req_headers):
            req_headers["Host"] = host if port in (80, 443) else f"{host}:{port}"

        # Clean CRLF and NUL from path_and_query (S3)
        clean_pq = path_and_query.replace("\r", "").replace("\n", "").replace("\0", "")
        if not clean_pq.startswith("/"):
            clean_pq = "/" + clean_pq

        req_lines = [f"{method} {clean_pq} HTTP/1.1\r\n"]
        for k, v in req_headers.items():
            k_clean = str(k).replace("\r", "").replace("\n", "")
            v_clean = str(v).replace("\r", "").replace("\n", "")
            req_lines.append(f"{k_clean}: {v_clean}\r\n")
        req_lines.append("\r\n")
        raw_req = "".join(req_lines).encode("latin-1")

        # Send request
        sock.settimeout(_sock_timeout())
        sock.sendall(raw_req)

        # Read response
        buf = bytearray()
        consecutive_1xx = 0

        while True:
            # Read until headers terminate (\r\n\r\n or \n\n)
            header_end = -1
            delim_len = 0
            while True:
                idx = buf.find(b"\r\n\r\n")
                if idx != -1:
                    header_end = idx
                    delim_len = 4
                    break
                idx = buf.find(b"\n\n")
                if idx != -1:
                    header_end = idx
                    delim_len = 2
                    break
                if len(buf) > 16384:
                    raise ValueError("headers_too_large")
                sock.settimeout(_sock_timeout())
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)

            if header_end == -1:
                if not buf:
                    raise ConnectionResetError("Connection closed before response")
                if len(buf) > 4096 and b"\n" not in buf[:4096]:
                    raise ValueError("status_line_too_long")
                raise ValueError("incomplete_response_headers")

            header_bytes = bytes(buf[:header_end])
            del buf[: header_end + delim_len]

            lines = header_bytes.split(b"\n")
            if not lines:
                raise ValueError("empty_response")
            status_line = lines[0].strip(b"\r")
            if len(status_line) > 4096:
                raise ValueError("status_line_too_long")

            try:
                status_str = status_line.decode("latin-1")
            except Exception:
                raise ValueError("invalid_status_line_encoding")

            parts = status_str.split(None, 2)
            if len(parts) < 2:
                raise ValueError(f"malformed_status_line:{status_str[:64]}")
            try:
                status_code = int(parts[1])
            except ValueError:
                raise ValueError(f"invalid_status_code:{parts[1]}")

            if 100 <= status_code < 200:
                consecutive_1xx += 1
                if consecutive_1xx > 3:
                    raise ValueError("too_many_1xx")
                continue

            # Parse headers
            header_lines = lines[1:]
            if len(header_lines) > 100:
                raise ValueError("too_many_header_lines")

            resp_headers: dict[str, str] = {}
            location_count = 0
            for h_line in header_lines:
                h_line = h_line.strip(b"\r")
                if not h_line:
                    continue
                colon_pos = h_line.find(b":")
                if colon_pos == -1:
                    continue
                name = (
                    h_line[:colon_pos]
                    .decode("latin-1", errors="replace")
                    .strip()
                    .lower()
                )
                val = (
                    h_line[colon_pos + 1 :]
                    .decode("latin-1", errors="replace")
                    .strip()
                )
                if name == "location":
                    location_count += 1
                if name in resp_headers:
                    resp_headers[name] = f"{resp_headers[name]}, {val}"
                else:
                    resp_headers[name] = val

            if location_count > 1:
                resp_headers["__ambiguous_location__"] = "true"

            break

        # Read body if not HEAD and not 204/304
        body = b""
        if method.upper() != "HEAD" and status_code not in (204, 304):
            cl_val = resp_headers.get("content-length")
            target_to_read = max_body_bytes
            if cl_val is not None:
                try:
                    cl_int = int(cl_val)
                    if cl_int >= 0:
                        target_to_read = min(max_body_bytes, cl_int)
                except ValueError:
                    pass

            while len(buf) < target_to_read:
                needed = min(4096, target_to_read - len(buf))
                sock.settimeout(_sock_timeout())
                chunk = sock.recv(needed)
                if not chunk:
                    break
                buf.extend(chunk)

            body = bytes(buf[:max_body_bytes])

        return status_code, resp_headers, body

    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _run_injected_transport(
    transport_fn: Callable,
    method: str,
    scheme: str,
    ip: str,
    port: int,
    host: str,
    path_and_query: str,
    headers: dict[str, str],
    timeout: float,
    max_body_bytes: int,
    deadline: float,
) -> tuple[int, dict[str, str], bytes]:
    """Execute injected/mock transport inside daemon worker thread with deadline timeout (B1(b))."""
    sig = None
    try:
        sig = inspect.signature(transport_fn)
        params = list(sig.parameters.keys())
    except Exception:
        params = []

    has_kwargs = False
    if sig:
        has_kwargs = any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )

    kwargs: dict[str, Any] = {}
    if "max_body_bytes" in params or has_kwargs:
        kwargs["max_body_bytes"] = max_body_bytes
    if "deadline" in params or has_kwargs:
        kwargs["deadline"] = deadline

    args = (method, scheme, ip, port, host, path_and_query, headers, timeout)

    result_box: list = []
    exc_box: list[Exception] = []
    done_event = threading.Event()

    def worker():
        try:
            res = transport_fn(*args, **kwargs)
            result_box.append(res)
        except Exception as e:
            exc_box.append(e)
        finally:
            done_event.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    rem = max(0.0, deadline - time.monotonic())
    wait_time = min(timeout, rem)
    finished = done_event.wait(timeout=wait_time)
    if not finished or time.monotonic() >= deadline:
        raise TimeoutError("budget_exceeded")

    if exc_box:
        raise exc_box[0]
    if result_box:
        return result_box[0]
    raise RuntimeError("transport_returned_no_result")


def _invoke_transport(
    transport_fn: Callable,
    method: str,
    scheme: str,
    ip: str,
    port: int,
    host: str,
    path_and_query: str,
    headers: dict[str, str],
    timeout: float,
    max_body_bytes: int,
    deadline: float,
) -> tuple[int, dict[str, str], bytes]:
    if transport_fn is default_transport:
        return default_transport(
            method=method,
            scheme=scheme,
            ip=ip,
            port=port,
            host=host,
            path_and_query=path_and_query,
            headers=headers,
            timeout=timeout,
            max_body_bytes=max_body_bytes,
            deadline=deadline,
        )
    return _run_injected_transport(
        transport_fn=transport_fn,
        method=method,
        scheme=scheme,
        ip=ip,
        port=port,
        host=host,
        path_and_query=path_and_query,
        headers=headers,
        timeout=timeout,
        max_body_bytes=max_body_bytes,
        deadline=deadline,
    )


@dataclass
class Hop:
    url: str
    status: int | None = None
    location: str | None = None
    ip: str | None = None
    flags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.url is not None:
            self.url = _sanitize_hop_str(self.url) or ""
        if self.location is not None:
            self.location = _sanitize_hop_str(self.location)

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "url": self.url,
            "status": self.status,
            "location": self.location,
            "ip": self.ip,
        }
        if self.flags:
            res["flags"] = list(self.flags)
        return res


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
        displayed_blocked = self.blocked_reason
        if displayed_blocked:
            if displayed_blocked in ("dns_error", "private_destination") or displayed_blocked.startswith(
                ("dns_error", "private_destination")
            ):
                displayed_blocked = "blocked_destination"

        return {
            "hops": [h.to_dict() for h in self.hops],
            "final_url": self.final_url,
            "blocked_reason": displayed_blocked,
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
        getaddrinfo: Callable | None = None,
        cache_ttl_s: int = 3600,
        cache_max: int = 512,
        *,
        _test_ip_filter: Callable[[str], bool] | None = None,
        _test_allowed_ports: tuple[int, ...] | None = None,
        allowed_ports: tuple[int, ...] = (80, 443),
        lists: dict[str, Any] | None = None,
        ip_validator: Any = None,
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
        if _test_ip_filter is None and ip_validator is not None:
            _test_ip_filter = ip_validator
        self._test_ip_filter = _test_ip_filter
        self.allowed_ports = (
            set(_test_allowed_ports)
            if _test_allowed_ports is not None
            else set(allowed_ports)
        )
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
            host = (parsed.effective_host or "").lower().rstrip(".")
            reg_dom = (getattr(parsed, "registrable_domain", "") or "").lower().rstrip(".")
            path = parsed.path or ""

            shorteners = {s.lower().rstrip(".") for s in self.lists.get("shorteners", [])}
            if host in shorteners or reg_dom in shorteners:
                return True

            redirectors = self.lists.get("redirectors", {})
            for k in redirectors.keys():
                k_low = k.lower().strip().rstrip(".")
                if "/" in k_low:
                    t_host, t_path = k_low.split("/", 1)
                    t_path = "/" + t_path.lstrip("/")
                    if host == t_host or host.endswith("." + t_host):
                        if (
                            path == t_path
                            or path.startswith(t_path + "/")
                            or path.startswith(t_path + "?")
                        ):
                            return True
                else:
                    if host == k_low or host.endswith("." + k_low):
                        return True

            return False

        return False

    def _validate_destination(
        self, host: str, port: int, timeout: float
    ) -> tuple[bool, str, list[str]]:
        """Validate destination using _test_ip_filter if injected, else is_public_destination."""
        gai = self.getaddrinfo if self.getaddrinfo is not None else socket.getaddrinfo
        return is_public_destination(
            host,
            port,
            getaddrinfo=gai,
            timeout=timeout,
            _test_ip_filter=self._test_ip_filter,
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
                error=f"internal_error:{type(e).__name__}",
                elapsed_ms=0.0,
                from_cache=False,
                antibot=None,
            )

    def _resolve_internal(self, url: str) -> RedirectChain:
        t_start = time.monotonic()
        deadline = t_start + self.total_budget

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

        # Parse initial URL (fragment dropped per S3)
        clean_url = urllib.parse.urldefrag(url.strip())[0]
        parsed = parse_url(clean_url)

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
        norm_key = clean_url
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
        current_url = clean_url
        blocked_reason: str | None = None
        error: str | None = None
        final_url: str | None = None
        antibot_data: dict | None = None
        retry_429_used: bool = False

        while True:
            # Check hops limit
            if len(hops) >= self.max_hops:
                error = "too_many_hops"
                break

            # Budget check
            remaining_budget = deadline - time.monotonic()
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
            if port not in self.allowed_ports:
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
            remaining_budget = deadline - time.monotonic()
            if remaining_budget <= 0:
                error = "budget_exceeded"
                break
            dns_timeout = min(self.per_hop_timeout, remaining_budget)
            ok, reason, ips = self._validate_destination(
                bare_host, port, timeout=dns_timeout
            )
            if not ok:
                if reason == "dns_busy":
                    blocked_reason = "dns_busy"
                elif "timeout" in reason:
                    if time.monotonic() >= deadline:
                        error = "budget_exceeded"
                    else:
                        error = "dns_timeout"
                elif "private" in reason or "loopback" in reason:
                    blocked_reason = "private_destination"
                elif "disallowed_host" in reason:
                    blocked_reason = "disallowed_host"
                elif "dns_error" in reason or "no_addresses_found" in reason:
                    blocked_reason = "dns_error"
                else:
                    blocked_reason = "blocked_destination"
                break

            if not ips:
                blocked_reason = "dns_error"
                break

            # Rule 5: Pin the IP address
            pinned_ip = ips[0]

            # Path and query - percent-encoded per S3, fragment dropped
            safe_path = urllib.parse.quote(p.path or "/", safe="/:@!$&'()*+,;=-_.~%")
            safe_query = (
                urllib.parse.quote(p.query, safe="&;=/?%-_.~!$'()*+,:@")
                if p.query
                else ""
            )
            path_and_query = safe_path + (f"?{safe_query}" if safe_query else "")

            host_hdr = host if port in (80, 443) else f"{host}:{port}"
            headers = {
                "Host": host_hdr,
                "User-Agent": "SafeGuardAI-LinkChecker/1.0",
                "Accept-Encoding": "identity",
            }

            transport_fn = self.transport or default_transport

            remaining_budget = deadline - time.monotonic()
            if remaining_budget <= 0:
                error = "budget_exceeded"
                break
            timeout = min(self.per_hop_timeout, remaining_budget)

            hop_flags: list[str] = []

            # Rule 6: Request HEAD first
            try:
                status, resp_headers, body = _invoke_transport(
                    transport_fn,
                    "HEAD",
                    p.scheme,
                    pinned_ip,
                    port,
                    host,
                    path_and_query,
                    headers,
                    timeout,
                    self.max_body_bytes,
                    deadline,
                )
            except Exception as e:
                if (
                    isinstance(e, (TimeoutError, socket.timeout))
                    or "budget_exceeded" in str(e)
                    or "timeout" in str(e).lower()
                ):
                    if time.monotonic() >= deadline or "budget_exceeded" in str(e):
                        error = "budget_exceeded"
                    else:
                        error = "request_timeout"
                elif "too_many_1xx" in str(e):
                    error = "transport_error:too_many_1xx"
                elif "ambiguous_location" in str(e):
                    error = "ambiguous_location"
                else:
                    error = f"transport_error:{type(e).__name__}"
                break

            resp_headers_lower = {
                str(k).lower(): str(v) for k, v in resp_headers.items()
            }

            # Retry at most once for 429 with Retry-After <= 5s within budget
            if status == 429 and not retry_429_used:
                retry_hdr = resp_headers_lower.get("retry-after")
                if retry_hdr:
                    try:
                        retry_s = float(retry_hdr.strip())
                    except (ValueError, TypeError):
                        retry_s = -1.0
                    if 0 <= retry_s <= 5.0:
                        rem = deadline - time.monotonic()
                        if rem > retry_s + 0.5:
                            time.sleep(retry_s)
                            retry_429_used = True
                            remaining_budget = deadline - time.monotonic()
                            if remaining_budget > 0:
                                timeout = min(self.per_hop_timeout, remaining_budget)
                                try:
                                    status, resp_headers, body = _invoke_transport(
                                        transport_fn,
                                        "HEAD",
                                        p.scheme,
                                        pinned_ip,
                                        port,
                                        host,
                                        path_and_query,
                                        headers,
                                        timeout,
                                        self.max_body_bytes,
                                        deadline,
                                    )
                                    resp_headers_lower = {
                                        str(k).lower(): str(v) for k, v in resp_headers.items()
                                    }
                                except Exception:
                                    pass

            if resp_headers_lower.get("__ambiguous_location__") == "true":
                error = "ambiguous_location"
                hops.append(
                    Hop(
                        url=current_url,
                        status=status,
                        location=resp_headers_lower.get("location"),
                        ip=pinned_ip,
                        flags=hop_flags,
                    )
                )
                break

            # If HEAD returns 405/501/403/429/503, fallback to GET
            # Note: 403, 429, 503 are retained because Phase 3B needs the body to detect antibot challenge pages
            if status in (405, 501, 403, 429, 503):
                remaining_budget = deadline - time.monotonic()
                if remaining_budget <= 0:
                    error = "budget_exceeded"
                    break
                timeout = min(self.per_hop_timeout, remaining_budget)
                try:
                    status, resp_headers, body = _invoke_transport(
                        transport_fn,
                        "GET",
                        p.scheme,
                        pinned_ip,
                        port,
                        host,
                        path_and_query,
                        headers,
                        timeout,
                        self.max_body_bytes,
                        deadline,
                    )
                except Exception as e:
                    if (
                        isinstance(e, (TimeoutError, socket.timeout))
                        or "budget_exceeded" in str(e)
                        or "timeout" in str(e).lower()
                    ):
                        if time.monotonic() >= deadline or "budget_exceeded" in str(e):
                            error = "budget_exceeded"
                        else:
                            error = "request_timeout"
                    elif "too_many_1xx" in str(e):
                        error = "transport_error:too_many_1xx"
                    elif "ambiguous_location" in str(e):
                        error = "ambiguous_location"
                    else:
                        error = f"transport_error:{type(e).__name__}"
                    break

                resp_headers_lower = {
                    str(k).lower(): str(v) for k, v in resp_headers.items()
                }
                if resp_headers_lower.get("__ambiguous_location__") == "true":
                    error = "ambiguous_location"
                    hops.append(
                        Hop(
                            url=current_url,
                            status=status,
                            location=resp_headers_lower.get("location"),
                            ip=pinned_ip,
                            flags=hop_flags,
                        )
                    )
                    break

            raw_location = resp_headers_lower.get("location")

            # S4: Meta refresh check for HEAD 2xx without Location
            if 200 <= status < 300 and not raw_location:
                ct = resp_headers_lower.get("content-type", "").lower()
                if not ct or "text/html" in ct:
                    remaining_budget = deadline - time.monotonic()
                    if remaining_budget > 0:
                        timeout = min(self.per_hop_timeout, remaining_budget)
                        try:
                            get_status, get_headers, get_body = _invoke_transport(
                                transport_fn,
                                "GET",
                                p.scheme,
                                pinned_ip,
                                port,
                                host,
                                path_and_query,
                                headers,
                                timeout,
                                self.max_body_bytes,
                                deadline,
                            )
                            body = get_body
                        except Exception:
                            pass

            # Truncate body if larger than max_body_bytes
            if body and len(body) > self.max_body_bytes:
                body = body[: self.max_body_bytes]

            body_str = ""
            if body:
                try:
                    body_str = body.decode("utf-8", errors="replace")
                except Exception:
                    body_str = str(body)

            # If status in (403, 429, 503) or explicit challenge header, check antibot immediately:
            is_explicit_antibot_candidate = (
                status in (403, 429, 503)
                or "cf-mitigated" in resp_headers_lower
                or "x-datadome" in resp_headers_lower
                or "x-amzn-waf-action" in resp_headers_lower
            )
            if is_explicit_antibot_candidate:
                bot_res = classify_response(status, resp_headers_lower, body_str)
                if bot_res is not None:
                    antibot_data = asdict(bot_res)
                    hops.append(
                        Hop(
                            url=current_url,
                            status=status,
                            location=raw_location,
                            ip=pinned_ip,
                            flags=hop_flags,
                        )
                    )
                    final_url = current_url
                    error = None
                    break

            # Check meta refresh if no HTTP redirect Location
            meta_refresh_url = None
            if not raw_location or status not in (301, 302, 303, 307, 308):
                if body_str:
                    meta_refresh_url = _extract_meta_refresh(body_str)

            redirect_target = (
                raw_location
                if (status in (301, 302, 303, 307, 308) and raw_location)
                else meta_refresh_url
            )

            if redirect_target:
                if len(redirect_target) > 2048:
                    error = "location_too_long"
                    hops.append(
                        Hop(
                            url=current_url,
                            status=status,
                            location=redirect_target,
                            ip=pinned_ip,
                            flags=hop_flags,
                        )
                    )
                    break

                # Normalize Location per WHATWG (S2)
                next_url, backslash_confusion = _normalize_location(
                    redirect_target, current_url
                )
                if backslash_confusion:
                    hop_flags.append("BACKSLASH_CONFUSION")

                # Check HTTPS -> HTTP downgrade (S8)
                if p.scheme == "https" and parse_url(next_url).scheme == "http":
                    hop_flags.append("DOWNGRADE_TO_HTTP")

                hops.append(
                    Hop(
                        url=current_url,
                        status=status,
                        location=redirect_target,
                        ip=pinned_ip,
                        flags=hop_flags,
                    )
                )

                if len(hops) >= self.max_hops:
                    error = "too_many_hops"
                    break

                current_url = next_url
                continue
            else:
                # Final hop reached - check for antibot on final response if not checked yet
                if antibot_data is None:
                    bot_res = classify_response(status, resp_headers_lower, body_str)
                    if bot_res is not None:
                        antibot_data = asdict(bot_res)
                        error = None

                hops.append(
                    Hop(
                        url=current_url,
                        status=status,
                        location=None,
                        ip=pinned_ip,
                        flags=hop_flags,
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
            antibot=antibot_data,
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
