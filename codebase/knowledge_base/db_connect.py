import os
import json
import sqlite3
import threading
import hashlib
from typing import Any


def _mask_client_id(cid: str | None) -> str:
    if not cid:
        return "none"
    return hashlib.sha256(cid.encode("utf-8")).hexdigest()[:8]


try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from codebase.config import get_settings
except ImportError:
    import sys
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
    from codebase.config import get_settings


class _CursorWrapper:
    """Helper context manager to support both stdlib sqlite3 cursors and MagicMock cursors."""
    def __init__(self, conn):
        self.conn = conn
        self.cursor = None

    def __enter__(self):
        raw = self.conn.cursor()
        if hasattr(raw, "__enter__"):
            self.cursor = raw.__enter__()
        else:
            self.cursor = raw
        return self.cursor

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self.cursor, "__exit__"):
            self.cursor.__exit__(exc_type, exc_val, exc_tb)
        elif hasattr(self.cursor, "close"):
            try:
                self.cursor.close()
            except Exception:
                pass


class SQLiteManager:
    """
    SQLite Database Manager for SafeGuardAI.
    Connects to SQLite database file (default: data/safeguard.db or SAFEGUARD_DB_PATH).
    Supports thread-safe operations, WAL mode, client isolation, and fail-open timeout semantics.
    """
    def __init__(self, db_path=None, host=None, user=None, password=None, database=None, port=None, force=False, **kwargs):
        settings = get_settings()
        self._lock = threading.Lock()
        self.db_path = db_path or os.environ.get("SAFEGUARD_DB_PATH") or getattr(settings, "db_path", "data/safeguard.db")
        self.conn = None
        self.is_connected = False
        if not force and (settings.offline or not settings.db_enabled) and db_path is None:
            return
        self._connect()
        if self.is_connected:
            self._ensure_schema()

    def _connect(self):
        settings = get_settings()
        db_to = getattr(settings, "db_timeout_s", 5.0)
        busy_timeout_ms = max(1000, int(db_to * 1000))
        try:
            if self.db_path != ":memory:":
                db_dir = os.path.dirname(os.path.abspath(self.db_path))
                if db_dir:
                    os.makedirs(db_dir, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=db_to)
            self.conn.row_factory = sqlite3.Row
            try:
                if self.db_path != ":memory:":
                    self.conn.execute("PRAGMA journal_mode=WAL;")
                self.conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms};")
                self.conn.execute("PRAGMA synchronous = NORMAL;")
            except Exception as pe:
                print(f"[SQLiteManager] PRAGMA notice: {pe}")
            self.is_connected = True
            print(f"[SQLiteManager] Successfully connected to SQLite Database `{self.db_path}`!")
        except Exception as e:
            print(f"[SQLiteManager] Notice: Could not connect to SQLite ({e}). System operating on JSON/In-memory fallback.")
            self.conn = None
            self.is_connected = False

    def _ping(self):
        if not self.is_connected or not self.conn:
            return
        try:
            if hasattr(self.conn, "ping"):
                self.conn.ping(reconnect=True)
            elif hasattr(self.conn, "execute"):
                self.conn.execute("SELECT 1")
        except Exception as e:
            print(f"[SQLiteManager] Notice: ping reconnect error (fail-open): {e}")

    def _ensure_schema(self):
        """Auto-creates user_logs table and indices, or migrates missing columns."""
        if not self.is_connected or not self.conn:
            return
        settings = get_settings()
        db_to = getattr(settings, "db_timeout_s", 5.0)
        acquired = self._lock.acquire(timeout=db_to)
        if not acquired:
            print("[SQLiteManager] Lock acquisition timeout during _ensure_schema (fail-open).")
            return
        try:
            with _CursorWrapper(self.conn) as cursor:
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS `user_logs` (
                    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                    `session_id` TEXT DEFAULT 'session_default',
                    `client_id` TEXT COLLATE BINARY DEFAULT NULL,
                    `user_text` TEXT NOT NULL,
                    `image_base64` TEXT,
                    `has_image` INTEGER DEFAULT 0,
                    `bot_response` TEXT,
                    `risk_score` INTEGER,
                    `risk_level` TEXT,
                    `confidence_score` INTEGER,
                    `matched_flags` TEXT,
                    `latency_ms` REAL DEFAULT 0,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS `idx_user_logs_session` ON `user_logs` (`session_id`);")
                cursor.execute("CREATE INDEX IF NOT EXISTS `idx_user_logs_client` ON `user_logs` (`client_id`);")

                # Schema evolution check for existing tables
                cursor.execute("PRAGMA table_info(`user_logs`);")
                rows = cursor.fetchall() or []
                existing_cols = {row[1] if isinstance(row, (list, tuple)) else row["name"] for row in rows}
                if "client_id" not in existing_cols:
                    cursor.execute("ALTER TABLE `user_logs` ADD COLUMN `client_id` TEXT COLLATE BINARY DEFAULT NULL;")
                if "has_image" not in existing_cols:
                    cursor.execute("ALTER TABLE `user_logs` ADD COLUMN `has_image` INTEGER DEFAULT 0;")
                if "image_base64" not in existing_cols:
                    cursor.execute("ALTER TABLE `user_logs` ADD COLUMN `image_base64` TEXT;")
                if "bot_response" not in existing_cols:
                    cursor.execute("ALTER TABLE `user_logs` ADD COLUMN `bot_response` TEXT;")
            if hasattr(self.conn, "commit"):
                self.conn.commit()
        except Exception as e:
            print(f"[SQLiteManager] Schema check notice: {e}")
        finally:
            self._lock.release()

    def log_user_analysis(
        self,
        user_text,
        risk_score,
        risk_level,
        confidence_score,
        matched_flags,
        latency_ms,
        session_id="session_default",
        bot_response="",
        image_base64=None,
        client_id=None
    ):
        """
        Logs user analysis results to `user_logs` table in SQLite database.
        """
        if not self.is_connected or not self.conn:
            return False

        settings = get_settings()
        has_image = 1 if image_base64 else 0
        stored_image = image_base64 if settings.store_images else None
        stored_client_id = None if (client_id and client_id.startswith("anonymous-")) else client_id

        db_to = getattr(settings, "db_timeout_s", 5.0)
        acquired = self._lock.acquire(timeout=db_to)
        if not acquired:
            print("[SQLiteManager] Lock acquisition timeout during log_user_analysis (fail-open).")
            return False
        try:
            self._ping()
            flags_str = ", ".join(matched_flags) if isinstance(matched_flags, list) else str(matched_flags)
            with _CursorWrapper(self.conn) as cursor:
                sql = """
                INSERT INTO `user_logs` (`session_id`, `client_id`, `user_text`, `image_base64`, `has_image`, `bot_response`, `risk_score`, `risk_level`, `confidence_score`, `matched_flags`, `latency_ms`)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cursor.execute(sql, (session_id, stored_client_id, user_text, stored_image, has_image, str(bot_response), risk_score, risk_level, confidence_score, flags_str, latency_ms))
            if hasattr(self.conn, "commit"):
                self.conn.commit()
            client_hash = _mask_client_id(client_id)
            print(f"[SQLiteManager] Logged analysis result for session `{session_id}` (client_hash={client_hash}) to SQLite.")
            return True
        except Exception as e:
            print(f"[SQLiteManager] Error logging analysis: {e}")
            return False
        finally:
            self._lock.release()

    def get_chat_history(self, session_id, client_id=None):
        """Fetches history of a specific session from SQLite database, optionally filtered by client_id."""
        if not self.is_connected or not self.conn:
            return []
        settings = get_settings()
        db_to = getattr(settings, "db_timeout_s", 5.0)
        acquired = self._lock.acquire(timeout=db_to)
        if not acquired:
            print("[SQLiteManager] Lock acquisition timeout during get_chat_history (fail-open).")
            return []
        rows = []
        try:
            self._ping()
            with _CursorWrapper(self.conn) as cursor:
                if client_id is not None:
                    sql = """
                    SELECT `user_text`, `image_base64`, `has_image`, `bot_response`, `risk_score`, `risk_level`, `created_at`
                    FROM `user_logs`
                    WHERE `session_id` = ? AND `client_id` = ? COLLATE BINARY
                    ORDER BY `id` ASC
                    """
                    cursor.execute(sql, (session_id, client_id))
                else:
                    sql = """
                    SELECT `user_text`, `image_base64`, `has_image`, `bot_response`, `risk_score`, `risk_level`, `created_at`
                    FROM `user_logs`
                    WHERE `session_id` = ?
                    ORDER BY `id` ASC
                    """
                    cursor.execute(sql, (session_id,))
                rows = cursor.fetchall() or []
        except Exception as e:
            print(f"[SQLiteManager] Error fetching chat history: {e}")
            return []
        finally:
            self._lock.release()

        processed = []
        for r in rows:
            row_dict = dict(r) if hasattr(r, "keys") else (dict(r) if isinstance(r, dict) else r)
            has_img = bool(row_dict.get("has_image") or row_dict.get("image_base64"))
            row_dict["has_image"] = has_img
            if not settings.store_images:
                row_dict["image_base64"] = ""
            processed.append(row_dict)
        return processed

    def get_all_sessions(self, client_id=None):
        """Returns distinct session IDs with title preview and latest timestamp (excluding benchmark test runs)."""
        if not self.is_connected or not self.conn:
            return []
        settings = get_settings()
        db_to = getattr(settings, "db_timeout_s", 5.0)
        acquired = self._lock.acquire(timeout=db_to)
        if not acquired:
            print("[SQLiteManager] Lock acquisition timeout during get_all_sessions (fail-open).")
            return []
        try:
            self._ping()
            with _CursorWrapper(self.conn) as cursor:
                if client_id is not None:
                    sql = """
                    SELECT `session_id`, MIN(`user_text`) as title, MAX(`created_at`) as last_active, COUNT(*) as msg_count
                    FROM `user_logs`
                    WHERE `session_id` NOT LIKE 'eval_%' AND `session_id` NOT LIKE 'session_test%' AND `client_id` = ? COLLATE BINARY
                    GROUP BY `session_id`
                    ORDER BY last_active DESC
                    """
                    cursor.execute(sql, (client_id,))
                else:
                    sql = """
                    SELECT `session_id`, MIN(`user_text`) as title, MAX(`created_at`) as last_active, COUNT(*) as msg_count
                    FROM `user_logs`
                    WHERE `session_id` NOT LIKE 'eval_%' AND `session_id` NOT LIKE 'session_test%'
                    GROUP BY `session_id`
                    ORDER BY last_active DESC
                    """
                    cursor.execute(sql)
                rows = cursor.fetchall() or []
                return [dict(r) if hasattr(r, "keys") else (dict(r) if isinstance(r, dict) else r) for r in rows]
        except Exception as e:
            print(f"[SQLiteManager] Error fetching sessions: {e}")
            return []
        finally:
            self._lock.release()

    def close(self):
        settings = get_settings()
        db_to = getattr(settings, "db_timeout_s", 5.0)
        acquired = self._lock.acquire(timeout=db_to)
        if not acquired:
            return
        try:
            if self.conn and self.is_connected:
                try:
                    self.conn.close()
                except Exception:
                    pass
                self.is_connected = False
                self.conn = None
        finally:
            self._lock.release()

    def __del__(self):
        self.close()


if __name__ == "__main__":
    db = SQLiteManager()
    if db.is_connected:
        db.log_user_analysis("Kiểm tra kết nối SQLite ai-anti-scam", 95, "HIGH", 98, ["tuyển dụng", "cọc tiền"], 12.5, "session_test", "Phát hiện rủi ro cao")
        history = db.get_chat_history("session_test")
        print(f"[SQLiteManager] Test history retrieved ({len(history)} items).")
        db.close()
