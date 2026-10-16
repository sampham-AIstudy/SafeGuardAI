import sys
import os
import json
import base64
import time
import uuid
import re
from io import BytesIO
from datetime import datetime, date
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote

# Add root project dir to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from codebase.config import get_settings
from codebase.orchestrator import SafeGuardOrchestrator


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


class SafeGuardAPIHandler(BaseHTTPRequestHandler):
    """
    REST API Handler & Static Web File Server for SafeGuard AI.
    Provides API endpoints for Multi-Agent analysis, MySQL persistence, and serves static HTML/CSS/JS.
    """
    timeout = 10
    server_version = "SafeGuardAI"

    def version_string(self):
        return self.server_version

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. API: Get all chat sessions from MySQL
        if path == '/api/sessions':
            self.send_json_response(orchestrator.db_manager.get_all_sessions())
            return

        # 2. API: Get history for specific session_id
        if path == '/api/history':
            query = parse_qs(parsed.query)
            session_id = query.get('session_id', ['session_default'])[0]
            if not SESSION_ID_PATTERN.fullmatch(session_id):
                self.send_json_response({"error": "Invalid session_id"}, status=400)
                return
            history = orchestrator.db_manager.get_chat_history(session_id)
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

        if path == '/api/analyze':
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
                try:
                    import select
                    r, _, _ = select.select([self.rfile], [], [], 0.02)
                    if r:
                        discard_bytes = min(content_length, 64 * 1024)
                        self.rfile.read(discard_bytes)
                except Exception:
                    pass
                self.send_json_response({"error": "Payload Too Large"}, status=413)
                return

            body = self.rfile.read(content_length)

            try:
                try:
                    data = json.loads(body.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
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

                # Process request through Multi-Agent Orchestrator
                result = orchestrator.process_request(
                    user_text=user_text,
                    image_input=image_input,
                    session_id=session_id,
                    image_base64=raw_image_base64
                )

                self.send_json_response(result)

            except Exception as e:
                err_id = str(uuid.uuid4())
                print(f"[Server Error {err_id}] Internal server error: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc()
                self.send_json_response({"error": "internal_error", "error_id": err_id}, status=500)
            return

        elif path == '/api/sessions/new':
            new_id = f"session_{int(time.time())}"
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
                self.send_header('Access-Control-Allow-Origin', '*')
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

    def send_json_response(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=self._json_default).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        if self.close_connection:
            self.send_header('Connection', 'close')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def create_server(host=None, port=None, handler_class=SafeGuardAPIHandler):
    settings = get_settings()
    h = host if host is not None else settings.host
    p = port if port is not None else settings.port
    server_address = (h, p)
    return HTTPServer(server_address, handler_class)


def run_server(host=None, port=None):
    _configure_streams()
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    httpd = create_server(host=host, port=port)
    actual_host, actual_port = httpd.server_address[:2]
    print(f"============================================================")
    print(f"🚀 SafeGuard AI Web App Server is RUNNING at:")
    print(f"👉 http://{actual_host}:{actual_port}")
    print(f"============================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SafeGuard AI Server...")
        httpd.server_close()


if __name__ == "__main__":
    run_server()

