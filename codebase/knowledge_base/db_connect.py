import os
import json

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

class MySQLManager:
    """
    MySQL Database Manager for XAMPP / MariaDB integration.
    Connects to MySQL database `ai-anti-scam` using environment variables from .env.
    Includes safe fallback to in-memory/JSON if MySQL service is not running.
    Supports Session-based Chat Memory persistence.
    """
    def __init__(self, host=None, user=None, password=None, database=None, port=None):
        settings = get_settings()
        self.host = host or os.environ.get("MYSQL_HOST", "localhost")
        self.user = user or os.environ.get("MYSQL_USER", "root")
        self.password = password if password is not None else os.environ.get("MYSQL_PASSWORD", "")
        self.database = database or os.environ.get("MYSQL_DATABASE", "ai-anti-scam")
        self.port = int(port or os.environ.get("MYSQL_PORT", 3306))
        self.conn = None
        self.is_connected = False
        if settings.offline or not settings.db_enabled:
            return
        self._connect()
        if self.is_connected:
            self._ensure_schema()

    def _connect(self):
        try:
            import pymysql
            self.conn = pymysql.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database,
                port=self.port,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            self.is_connected = True
            print(f"[MySQLManager] Successfully connected to MariaDB/MySQL Database `{self.database}` on port {self.port}!")
            return
        except ImportError:
            pass
        except Exception as e:
            print(f"[MySQLManager] Notice: Could not connect to MySQL ({e}). System operating on JSON/In-memory fallback.")
            return

        try:
            import mysql.connector
            self.conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database,
                port=self.port
            )
            self.is_connected = True
            print(f"[MySQLManager] Successfully connected via mysql-connector to `{self.database}`!")
            return
        except ImportError:
            print("[MySQLManager] Notice: Missing `pymysql` module. Please run: pip install pymysql")
        except Exception as e:
            print(f"[MySQLManager] Notice: Could not connect to MySQL ({e}). System operating on JSON/In-memory fallback.")

    def _ensure_schema(self):
        """Auto-migrates schema to add session_id & bot_response columns if missing."""
        if not self.is_connected or not self.conn:
            return
        try:
            with self.conn.cursor() as cursor:
                # Check columns in user_logs
                cursor.execute("SHOW COLUMNS FROM `user_logs` LIKE 'session_id'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE `user_logs` ADD COLUMN `session_id` VARCHAR(100) DEFAULT 'session_default' AFTER `id`")
                    cursor.execute("ALTER TABLE `user_logs` ADD INDEX `idx_session` (`session_id`)")

                cursor.execute("SHOW COLUMNS FROM `user_logs` LIKE 'bot_response'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE `user_logs` ADD COLUMN `bot_response` TEXT AFTER `user_text`")

                cursor.execute("SHOW COLUMNS FROM `user_logs` LIKE 'image_base64'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE `user_logs` ADD COLUMN `image_base64` LONGTEXT AFTER `user_text`")
            self.conn.commit()
        except Exception as e:
            print(f"[MySQLManager] Schema check notice: {e}")

    def log_user_analysis(self, user_text, risk_score, risk_level, confidence_score, matched_flags, latency_ms, session_id="session_default", bot_response="", image_base64=None):
        """
        Logs user analysis results to `user_logs` table in MySQL database `ai-anti-scam`.
        """
        if not self.is_connected or not self.conn:
            return False

        try:
            with self.conn.cursor() as cursor:
                sql = """
                INSERT INTO `user_logs` (`session_id`, `user_text`, `image_base64`, `bot_response`, `risk_score`, `risk_level`, `confidence_score`, `matched_flags`, `latency_ms`)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                flags_str = ", ".join(matched_flags) if isinstance(matched_flags, list) else str(matched_flags)
                cursor.execute(sql, (session_id, user_text, image_base64, str(bot_response), risk_score, risk_level, confidence_score, flags_str, latency_ms))
            self.conn.commit()
            print(f"[MySQLManager] Logged analysis result for session `{session_id}` to MySQL.")
            return True
        except Exception as e:
            print(f"[MySQLManager] Error logging analysis: {e}")
            return False

    def get_chat_history(self, session_id):
        """Fetches history of a specific session from MySQL database."""
        if not self.is_connected or not self.conn:
            return []
        try:
            with self.conn.cursor() as cursor:
                sql = "SELECT `user_text`, `image_base64`, `bot_response`, `risk_score`, `risk_level`, `created_at` FROM `user_logs` WHERE `session_id` = %s ORDER BY `id` ASC"
                cursor.execute(sql, (session_id,))
                rows = cursor.fetchall()
                return rows
        except Exception as e:
            print(f"[MySQLManager] Error fetching chat history: {e}")
            return []

    def get_all_sessions(self):
        """Returns distinct session IDs with title preview and latest timestamp (excluding benchmark test runs)."""
        if not self.is_connected or not self.conn:
            return []
        try:
            with self.conn.cursor() as cursor:
                sql = """
                SELECT `session_id`, MIN(`user_text`) as title, MAX(`created_at`) as last_active, COUNT(*) as msg_count
                FROM `user_logs`
                WHERE `session_id` NOT LIKE 'eval_%' AND `session_id` NOT LIKE 'session_test%'
                GROUP BY `session_id`
                ORDER BY last_active DESC
                """
                cursor.execute(sql)
                return cursor.fetchall()
        except Exception as e:
            print(f"[MySQLManager] Error fetching sessions: {e}")
            return []

    def close(self):
        if self.conn and self.is_connected:
            try:
                self.conn.close()
            except Exception:
                pass
            self.is_connected = False
            self.conn = None

    def __del__(self):
        self.close()

if __name__ == "__main__":
    db = MySQLManager()
    if db.is_connected:
        db.log_user_analysis("Kiểm tra kết nối MariaDB/MySQL ai-anti-scam từ .env", 95, "HIGH", 98, ["tuyển dụng", "cọc tiền"], 12.5, "session_test", "Phát hiện rủi ro cao")
        history = db.get_chat_history("session_test")
        print(f"[MySQLManager] Test history retrieved ({len(history)} items).")
        db.close()
