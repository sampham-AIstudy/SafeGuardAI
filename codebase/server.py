import sys
import os
import json
import base64
import time
from io import BytesIO
from datetime import datetime, date
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Add root project dir to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from codebase.orchestrator import SafeGuardOrchestrator

# Initialize global Orchestrator
orchestrator = SafeGuardOrchestrator()
PUBLIC_DIR = os.path.join(os.path.dirname(__file__), "..", "public")

class SafeGuardAPIHandler(BaseHTTPRequestHandler):
    """
    REST API Handler & Static Web File Server for SafeGuard AI.
    Provides API endpoints for Multi-Agent analysis, MySQL persistence, and serves static HTML/CSS/JS.
    """

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
            history = orchestrator.db_manager.get_chat_history(session_id)
            self.send_json_response(history)
            return

        # 3. Serve Static Web Files (HTML, CSS, JS, Images & Assets)
        rel_path = path.lstrip('/')
        if not rel_path or rel_path == 'index.html':
            rel_path = 'index.html'

        target_file = os.path.normpath(os.path.join(PUBLIC_DIR, rel_path))
        if target_file.startswith(os.path.normpath(PUBLIC_DIR)) and os.path.isfile(target_file):
            ext = os.path.splitext(target_file)[1].lower()
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
            self.serve_file(target_file, mime)
            return
        else:
            self.send_error(404, f"File Not Found: {path}")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/analyze':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            try:
                data = json.loads(body.decode('utf-8'))
                user_text = data.get('user_text', '')
                session_id = data.get('session_id', 'session_default')
                raw_image_base64 = data.get('image_base64', None)

                image_input = None
                if raw_image_base64:
                    b64_str = raw_image_base64
                    if ',' in b64_str:
                        b64_str = b64_str.split(',')[1]
                    img_bytes = base64.b64decode(b64_str)
                    image_input = BytesIO(img_bytes)

                # Process request through Multi-Agent Orchestrator
                result = orchestrator.process_request(
                    user_text=user_text,
                    image_input=image_input,
                    session_id=session_id,
                    image_base64=raw_image_base64
                )

                self.send_json_response(result)

            except Exception as e:
                print(f"[Server Error] {e}")
                self.send_json_response({"error": str(e)}, status=500)
            return

        elif path == '/api/sessions/new':
            new_id = f"session_{int(time.time())}"
            self.send_json_response({"session_id": new_id, "title": "Cuộc trò chuyện mới"})
            return

        self.send_error(404, "Endpoint Not Found")

    def serve_file(self, filepath, mime_type):
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, f"File {os.path.basename(filepath)} missing")

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
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run_server(port=8000):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    server_address = ('', port)
    httpd = HTTPServer(server_address, SafeGuardAPIHandler)
    print(f"============================================================")
    print(f"🚀 SafeGuard AI Web App Server is RUNNING at:")
    print(f"👉 http://localhost:{port}")
    print(f"============================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SafeGuard AI Server...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
