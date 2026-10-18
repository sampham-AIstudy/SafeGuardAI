import sys
import os
import json
import base64
import time
import uuid
import re
import socket
import secrets
import hmac
import ipaddress
import threading
import hashlib
import math
from collections import OrderedDict
from io import BytesIO
from datetime import datetime, date
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote

# Add root project dir to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from codebase.config import get_settings
from codebase.orchestrator import SafeGuardOrchestrator

# Secret generated randomly in RAM on startup; never persisted to disk (S1)
_SERVER_ANON_SECRET = secrets.token_bytes(32)


def _configure_streams():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


_configure_streams()

# Initialize global Orchestrator
orchestrator = SafeGuardOrchestrator()
PUBLIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "public"))
SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,100}$", re.ASCII)
CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$", re.ASCII)


class TokenBucketRateLimiter:
    """
    Thread-safe Token Bucket rate limiter with bounded LRU memory.
    Burst = min(10, rate_per_min) by default, or configurable.
    Bounded IP tracking table to prevent unbounded memory growth.
    """
    def __init__(self, rate_per_min: int = 20, max_ips: int = 10_000, clock=None, burst: float | None = None):
        self.rate_per_min = rate_per_min
        self.rate_per_sec = rate_per_min / 60.0
        self.burst = float(burst) if burst is not None else float(min(10, rate_per_min))
        self.max_ips = max_ips
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._buckets = OrderedDict()  # ip -> (tokens, last_time)

    def check_and_consume(self, ip: str, tokens_needed: float = 1.0) -> tuple[bool, float]:
        now = self._clock()
        with self._lock:
            if ip in self._buckets:
                self._buckets.move_to_end(ip)
                tokens, last_time = self._buckets[ip]
                elapsed = max(0.0, now - last_time)
                tokens = min(self.burst, tokens + elapsed * self.rate_per_sec)
            else:
                if len(self._buckets) >= self.max_ips:
                    self._buckets.popitem(last=False)
                tokens = self.burst
                last_time = now

            if tokens >= tokens_needed:
                tokens -= tokens_needed
                self._buckets[ip] = (tokens, now)
                return True, 0.0
            else:
                deficit = tokens_needed - tokens
                wait_time = deficit / self.rate_per_sec if self.rate_per_sec > 0 else 60.0
                self._buckets[ip] = (tokens, now)
                return False, max(1.0, wait_time)

    def reset(self):
        with self._lock:
            self._buckets.clear()


_DEFAULT_SEMAPHORE = threading.BoundedSemaphore(4)
_DEFAULT_RATE_LIMITER = TokenBucketRateLimiter(20, max_ips=10_000)
_DEFAULT_HEALTH_RATE_LIMITER = TokenBucketRateLimiter(60, max_ips=10_000)
_DEFAULT_SESSION_RATE_LIMITER = TokenBucketRateLimiter(60, max_ips=10_000, burst=60)


def _normalize_ip(ip_str: str) -> str:
    """Normalize IP string, converting IPv4-mapped IPv6 (::ffff:1.2.3.4) to pure IPv4."""
    try:
        obj = ipaddress.ip_address(ip_str.strip())
        if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped:
            return str(obj.ipv4_mapped)
        return str(obj)
    except ValueError:
        return ip_str.strip() or "127.0.0.1"


def get_client_ip(handler) -> str:
    """
    Extract client IP address safely:
    - Connection IP is the default fallback.
    - If SAFEGUARD_TRUST_PROXY=1:
      - Ignores X-Forwarded-For if longer than 512 characters.
      - Takes the N-th hop from the right (SAFEGUARD_TRUSTED_PROXY_HOPS, default 1: rightmost).
      - Strictly validates with ipaddress.ip_address (invalid => fallback to connection IP).
      - Normalizes IPv4-mapped IPv6 (::ffff:1.2.3.4) to pure IPv4 (1.2.3.4).
    """
    conn_ip = "127.0.0.1"
    if hasattr(handler, "client_address") and handler.client_address and len(handler.client_address) > 0:
        conn_ip = str(handler.client_address[0])
    normalized_conn_ip = _normalize_ip(conn_ip)

    settings = get_settings()
    trust_proxy = getattr(settings, "trust_proxy", False) or (os.environ.get("SAFEGUARD_TRUST_PROXY") == "1")
    if not trust_proxy or not hasattr(handler, "headers") or not handler.headers:
        return normalized_conn_ip

    xff = handler.headers.get("X-Forwarded-For")
    if not xff:
        return normalized_conn_ip

    if len(xff) > 512:
        return normalized_conn_ip

    hops = [h.strip() for h in xff.split(",") if h.strip()]
    if not hops:
        return normalized_conn_ip

    n_hops = getattr(settings, "trusted_proxy_hops", 1)
    try:
        n_hops = max(1, int(n_hops))
    except (ValueError, TypeError):
        n_hops = 1

    target_hop = hops[-n_hops] if len(hops) >= n_hops else hops[0]

    try:
        ip_obj = ipaddress.ip_address(target_hop)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            return str(ip_obj.ipv4_mapped)
        return str(ip_obj)
    except ValueError:
        return normalized_conn_ip


def _check_json_depth(text: str, max_depth: int = 200) -> bool:
    """
    Check maximum nesting depth of JSON structures ('[' and '{') to prevent RecursionError DoS.
    Returns False if depth exceeds max_depth.
    """
    depth = 0
    in_string = False
    escape = False
    for ch in text:
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if not in_string:
            if ch in ('{', '['):
                depth += 1
                if depth > max_depth:
                    return False
            elif ch in ('}', ']'):
                if depth > 0:
                    depth -= 1
    return True


class SafeGuardAPIHandler(BaseHTTPRequestHandler):
    """
    REST API Handler & Static Web File Server for SafeGuard AI.
    Provides API endpoints for Multi-Agent analysis, MySQL persistence, and serves static HTML/CSS/JS.
    """
    timeout = 10
    server_version = "SafeGuardAI"

    def _drain_and_close(self, max_bytes: int = 1_048_576, timeout_s: float = 2.0):
        """
        Gracefully shutdown write side and drain unread incoming body bytes
        to prevent client receiving connection reset (TCP RST).
        Limits discarding to max_bytes (default 1MB) or timeout_s (default 2s).
        """
        self.close_connection = True
        try:
            if hasattr(self, "wfile") and self.wfile:
                try:
                    self.wfile.flush()
                except Exception:
                    pass
            if hasattr(self, "connection") and self.connection:
                try:
                    self.connection.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                try:
                    self.connection.settimeout(min(timeout_s, 0.5))
                except Exception:
                    pass
            bytes_drained = 0
            chunk_size = 65536
            t_start = time.monotonic()
            while bytes_drained < max_bytes and (time.monotonic() - t_start) < timeout_s:
                to_read = min(chunk_size, max_bytes - bytes_drained)
                try:
                    if hasattr(self, "connection") and self.connection:
                        chunk = self.connection.recv(to_read)
                    else:
                        chunk = self.rfile.read(to_read)
                    if not chunk:
                        break
                    bytes_drained += len(chunk)
                except (socket.timeout, TimeoutError, OSError, AttributeError):
                    break
        except Exception:
            pass

    def version_string(self):
        return self.server_version

    def end_headers(self):
        # Security Headers for all responses
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )

        # Cache-Control for API routes
        if hasattr(self, "path") and self.path and self.path.startswith('/api/'):
            self.send_header('Cache-Control', 'no-store')

        # CORS allowlist check (exact match, no wildcard)
        origin = self.headers.get('Origin') if (hasattr(self, "headers") and self.headers) else None
        if origin:
            settings = get_settings()
            cors_origins = getattr(settings, "cors_origins", ())
            if not cors_origins:
                raw_cors = os.environ.get("SAFEGUARD_CORS_ORIGINS", "").strip()
                if raw_cors:
                    cors_origins = tuple(o.strip() for o in raw_cors.split(",") if o.strip())
            if origin in cors_origins:
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Vary', 'Origin')

        super().end_headers()

    def do_OPTIONS(self):
        origin = self.headers.get('Origin')
        settings = get_settings()
        cors_origins = getattr(settings, "cors_origins", ())
        if not cors_origins:
            raw_cors = os.environ.get("SAFEGUARD_CORS_ORIGINS", "").strip()
            if raw_cors:
                cors_origins = tuple(o.strip() for o in raw_cors.split(",") if o.strip())

        if origin and origin in cors_origins:
            self.send_response(200)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Client-Id')
            self.end_headers()
        else:
            self.send_error(403, "Forbidden Origin")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 0. API: Health status (light rate limit 60/min/ip, no X-Client-Id required)
        if path in ('/api/health', '/api/health/'):
            limiter = getattr(self.server, "health_rate_limiter", _DEFAULT_HEALTH_RATE_LIMITER)
            client_ip = get_client_ip(self)
            allowed, wait_s = limiter.check_and_consume(client_ip)
            if not allowed:
                err_id = str(uuid.uuid4())
                retry_str = str(max(1, int(math.ceil(wait_s))))
                self.send_json_response(
                    {"error": "rate_limited", "error_id": err_id},
                    status=429,
                    headers={"Retry-After": retry_str}
                )
                return
            self.send_json_response(orchestrator.health_info())
            return

        # 1. API: Get all chat sessions from MySQL (client-isolated, rate limited 60/min/IP)
        if path == '/api/sessions':
            limiter = getattr(self.server, "session_rate_limiter", _DEFAULT_SESSION_RATE_LIMITER)
            client_ip = get_client_ip(self)
            allowed, wait_s = limiter.check_and_consume(client_ip)
            if not allowed:
                err_id = str(uuid.uuid4())
                retry_str = str(max(1, int(math.ceil(wait_s))))
                self.send_json_response(
                    {"error": "rate_limited", "error_id": err_id},
                    status=429,
                    headers={"Retry-After": retry_str}
                )
                return

            client_id = self.headers.get('X-Client-Id')
            if not client_id or not CLIENT_ID_PATTERN.fullmatch(client_id) or client_id.startswith('anonymous-'):
                self.send_json_response({"error": "Missing or invalid X-Client-Id header"}, status=400)
                return
            sessions = orchestrator.db_manager.get_all_sessions(client_id=client_id)
            self.send_json_response(sessions)
            return

        # 2. API: Get history for specific session_id (client-isolated, rate limited 60/min/IP)
        if path == '/api/history':
            limiter = getattr(self.server, "session_rate_limiter", _DEFAULT_SESSION_RATE_LIMITER)
            client_ip = get_client_ip(self)
            allowed, wait_s = limiter.check_and_consume(client_ip)
            if not allowed:
                err_id = str(uuid.uuid4())
                retry_str = str(max(1, int(math.ceil(wait_s))))
                self.send_json_response(
                    {"error": "rate_limited", "error_id": err_id},
                    status=429,
                    headers={"Retry-After": retry_str}
                )
                return

            client_id = self.headers.get('X-Client-Id')
            if not client_id or not CLIENT_ID_PATTERN.fullmatch(client_id) or client_id.startswith('anonymous-'):
                self.send_json_response({"error": "Missing or invalid X-Client-Id header"}, status=400)
                return
            query = parse_qs(parsed.query)
            session_id = query.get('session_id', ['session_default'])[0]
            if not SESSION_ID_PATTERN.fullmatch(session_id):
                self.send_json_response({"error": "Invalid session_id"}, status=400)
                return
            history = orchestrator.db_manager.get_chat_history(session_id=session_id, client_id=client_id)
            self.send_json_response(history)
            return

        # 3. Serve Static Web Files (HTML, CSS, JS, Images & Assets)
        # (1) Unquote path first and reject immediately BEFORE touching filesystem:
        raw_path = unquote(self.path)
        if ('\\' in raw_path or 
            ':' in raw_path or 
            '\x00' in raw_path or 
            raw_path.startswith('//')):
            self.send_error(404, "File Not Found")
            return

        clean_path = raw_path.split('?')[0].strip('/')
        parts = clean_path.split('/') if clean_path else []
        if any(part in ('..', '.') for part in parts):
            self.send_error(404, "File Not Found")
            return

        if not clean_path or clean_path == 'index.html':
            clean_path = 'index.html'

        # (2) Check inside public/ using string check (os.path.normpath + commonpath, NO resolve on raw client path)
        try:
            public_root = os.path.normpath(os.path.abspath(PUBLIC_DIR))
            target_path = os.path.normpath(os.path.join(public_root, clean_path))

            is_inside = os.path.commonpath([public_root, target_path]) == public_root
            if not is_inside:
                self.send_error(404, "File Not Found")
                return

            # (3) Wrap serving in try/except (OSError, ValueError) returning 404
            if os.path.isfile(target_path):
                ext = os.path.splitext(target_path)[1].lower()
                mime_types = {
                    '.html': 'text/html; charset=utf-8',
                    '.css': 'text/css; charset=utf-8',
                    '.js': 'application/javascript; charset=utf-8',
                    '.jpg': 'image/jpeg',
                    '.jpeg': 'image/jpeg',
                    '.png': 'image/png',
                    '.gif': 'image/gif',
                    '.svg': 'image/svg+xml',
                    '.webp': 'image/webp',
                    '.ico': 'image/x-icon'
                }
                mime = mime_types.get(ext, 'application/octet-stream')
                self.serve_file(target_path, mime)
                return
            else:
                self.send_error(404, "File Not Found")
                return
        except (OSError, ValueError):
            self.send_error(404, "File Not Found")
            return

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ('/api/health', '/api/health/'):
            self.send_json_response(
                {"error": "Method Not Allowed"},
                status=405,
                headers={"Allow": "GET"}
            )
            return

        if path == '/api/analyze':
            # Rate limiting check
            limiter = getattr(self.server, "rate_limiter", _DEFAULT_RATE_LIMITER)
            client_ip = get_client_ip(self)
            allowed, wait_s = limiter.check_and_consume(client_ip)
            if not allowed:
                err_id = str(uuid.uuid4())
                retry_str = str(max(1, int(math.ceil(wait_s))))
                self.close_connection = True
                self.send_json_response(
                    {"error": "rate_limited", "error_id": err_id},
                    status=429,
                    headers={"Retry-After": retry_str, "Connection": "close"}
                )
                self._drain_and_close(max_bytes=1_048_576, timeout_s=2.0)
                return

            cl_header = self.headers.get('Content-Length')
            if cl_header is None:
                self.close_connection = True
                self.send_json_response({"error": "Missing Content-Length header"}, status=400)
                return
            try:
                content_length = int(cl_header)
                if content_length < 0:
                    raise ValueError("Negative Content-Length")
            except (ValueError, TypeError):
                self.close_connection = True
                self.send_json_response({"error": "Invalid Content-Length header"}, status=400)
                return

            max_body = get_settings().max_body_bytes
            if content_length > max_body:
                self.close_connection = True
                self.send_json_response(
                    {"error": "Payload Too Large"},
                    status=413,
                    headers={"Connection": "close"}
                )
                self._drain_and_close(max_bytes=1_048_576, timeout_s=2.0)
                return

            body = self.rfile.read(content_length)

            try:
                try:
                    decoded_body = body.decode('utf-8')
                except UnicodeDecodeError:
                    self.send_json_response({"error": "Malformed JSON"}, status=400)
                    return

                if not _check_json_depth(decoded_body, max_depth=200):
                    self.send_json_response({"error": "JSON depth exceeds maximum allowed limit"}, status=400)
                    return

                try:
                    data = json.loads(decoded_body)
                except (json.JSONDecodeError, RecursionError):
                    self.send_json_response({"error": "Malformed JSON"}, status=400)
                    return

                if not isinstance(data, dict):
                    self.send_json_response({"error": "JSON body must be an object"}, status=400)
                    return

                # Validate types
                user_text = data.get('user_text', '')
                if not isinstance(user_text, str):
                    self.send_json_response({"error": "user_text must be a string"}, status=400)
                    return

                session_id = data.get('session_id', 'session_default')
                if not isinstance(session_id, str) or not SESSION_ID_PATTERN.fullmatch(session_id):
                    self.send_json_response({"error": "Invalid session_id: must match ^[\\w-]{1,100}$"}, status=400)
                    return

                # Validate online_check flag (P1)
                if 'online_check' in data:
                    raw_online = data['online_check']
                    if not isinstance(raw_online, bool):
                        self.send_json_response({"error": "online_check must be a boolean"}, status=400)
                        return
                    online_check = raw_online
                else:
                    online_check = False

                raw_image_base64 = data.get('image_base64', None)
                if raw_image_base64 is not None and not isinstance(raw_image_base64, str):
                    self.send_json_response({"error": "image_base64 must be string or null"}, status=400)
                    return

                image_input = None
                if raw_image_base64:
                    b64_str = raw_image_base64
                    if ',' in b64_str:
                        b64_str = b64_str.split(',')[1]
                    try:
                        img_bytes = base64.b64decode(b64_str, validate=True)
                        image_input = BytesIO(img_bytes)
                    except Exception:
                        self.send_json_response({"error": "Dữ liệu ảnh base64 không hợp lệ."}, status=400)
                        return

                # Validate client_id header
                raw_client_id = self.headers.get('X-Client-Id')
                if raw_client_id is not None:
                    if not CLIENT_ID_PATTERN.fullmatch(raw_client_id):
                        self.send_json_response({"error": "Invalid X-Client-Id header"}, status=400)
                        return
                    client_id = raw_client_id
                else:
                    ip_hmac = hmac.new(_SERVER_ANON_SECRET, client_ip.encode('utf-8'), hashlib.sha256).hexdigest()[:32]
                    client_id = f"anonymous-{ip_hmac}"

                # Concurrency Semaphore check (wait up to 5s)
                sem = getattr(self.server, "analyze_semaphore", _DEFAULT_SEMAPHORE)
                acquired = sem.acquire(timeout=5.0)
                if not acquired:
                    err_id = str(uuid.uuid4())
                    self.send_json_response(
                        {"error": "busy", "error_id": err_id},
                        status=503,
                        headers={"Retry-After": "2"}
                    )
                    return

                try:
                    # Process request through Multi-Agent Orchestrator
                    result = orchestrator.process_request(
                        user_text=user_text,
                        image_input=image_input,
                        session_id=session_id,
                        image_base64=raw_image_base64,
                        online_check=online_check,
                        client_id=client_id,
                    )
                    self.send_json_response(result)
                finally:
                    sem.release()

            except Exception as e:
                err_id = str(uuid.uuid4())
                print(f"[Server Error {err_id}] Internal server error occurred", file=sys.stderr)
                self.send_json_response({"error": "internal_error", "error_id": err_id}, status=500)
            return

        elif path == '/api/sessions/new':
            # Rate limiting check
            limiter = getattr(self.server, "rate_limiter", _DEFAULT_RATE_LIMITER)
            client_ip = get_client_ip(self)
            allowed, wait_s = limiter.check_and_consume(client_ip)
            if not allowed:
                err_id = str(uuid.uuid4())
                retry_str = str(max(1, int(math.ceil(wait_s))))
                self.send_json_response(
                    {"error": "rate_limited", "error_id": err_id},
                    status=429,
                    headers={"Retry-After": retry_str}
                )
                return

            new_id = f"session_{uuid.uuid4()}"
            self.send_json_response({"session_id": new_id, "title": "Cuộc trò chuyện mới"})
            return

        self.send_error(404, "Endpoint Not Found")

    def serve_file(self, filepath, mime_type):
        try:
            if os.path.isfile(filepath):
                with open(filepath, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', mime_type)
                if self.close_connection:
                    self.send_header('Connection', 'close')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "File Not Found")
        except (OSError, ValueError):
            self.send_error(404, "File Not Found")

    def _json_default(self, obj):
        """Custom JSON serializer for objects not serializable by default json encoder."""
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if hasattr(obj, "items"):
            return {str(k): self._json_default(v) for k, v in obj.items()}
        if hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes)):
            return [self._json_default(x) for x in obj]
        return str(obj)

    def send_json_response(self, data, status=200, headers=None):
        body = json.dumps(data, ensure_ascii=False, default=self._json_default).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        if headers:
            for k, v in headers.items():
                self.send_header(k, str(v))
        if self.close_connection:
            self.send_header('Connection', 'close')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SafeGuardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)
        settings = get_settings()
        max_conc = max(1, min(16, getattr(settings, "max_concurrency", 4)))
        self.analyze_semaphore = threading.BoundedSemaphore(max_conc)
        self.rate_limiter = TokenBucketRateLimiter(rate_per_min=settings.rate_limit_per_min, max_ips=10_000)
        self.health_rate_limiter = TokenBucketRateLimiter(rate_per_min=60, max_ips=10_000)
        self.session_rate_limiter = TokenBucketRateLimiter(rate_per_min=60, max_ips=10_000, burst=60)
        self._active_connections = 0
        self._conn_lock = threading.Lock()

    def process_request(self, request, client_address):
        settings = get_settings()
        max_conn = getattr(settings, "max_connections", 256)
        with self._conn_lock:
            if self._active_connections >= max_conn:
                try:
                    request.sendall(
                        b"HTTP/1.1 503 Service Unavailable\r\n"
                        b"Content-Type: text/plain; charset=utf-8\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 19\r\n\r\n"
                        b"Server at capacity\n"
                    )
                except Exception:
                    pass
                try:
                    request.close()
                except Exception:
                    pass
                return
            self._active_connections += 1
        super().process_request(request, client_address)

    def close_request(self, request):
        with self._conn_lock:
            if self._active_connections > 0:
                self._active_connections -= 1
        super().close_request(request)


def create_server(host=None, port=None, handler_class=SafeGuardAPIHandler):
    settings = get_settings()
    h = host if host is not None else settings.host
    p = port if port is not None else settings.port
    server_address = (h, p)
    server = SafeGuardServer(server_address, handler_class)
    return server


def run_server(host=None, port=None):
    _configure_streams()
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    t_warm = time.perf_counter()
    warm_res = orchestrator.warm_up()
    warm_dur = time.perf_counter() - t_warm
    print(f"🔥 SafeGuard AI Warm-up hoàn tất trong {warm_dur:.2f}s (status: {warm_res.get('status', 'ok')})")
    httpd = create_server(host=host, port=port)
    actual_host, actual_port = httpd.server_address[:2]
    print(f"============================================================")
    print(f"🚀 SafeGuard AI Web App Server is RUNNING at:")
    print(f"👉 http://{actual_host}:{actual_port}")
    if str(actual_host) not in ("127.0.0.1", "localhost", "::1"):
        print(f"⚠️ CẢNH BÁO: Server mở ra mạng LAN ({actual_host}): bật xác thực/proxy!")
    print(f"============================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SafeGuard AI Server...")
        httpd.server_close()


if __name__ == "__main__":
    run_server()
