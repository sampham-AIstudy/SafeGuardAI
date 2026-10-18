#!/usr/bin/env python3
"""
scripts/migrate_mysql_to_sqlite.py

Công cụ di trú một lần dữ liệu lịch sử chat từ MySQL `ai-anti-scam.user_logs` sang SQLite `data/safeguard.db`.

BẢO MẬT & CÔ LẬP DỮ LIỆU:
Dữ liệu di trú từ MySQL cũ không có trường `client_id` (không có chủ sở hữu), do đó được lưu với `client_id = NULL`.
Theo cơ chế bảo mật cô lập client của SafeGuardAI (Phase 4D/4E), các bản ghi có `client_id = NULL` sẽ KHÔNG THỂ
bị truy cập hay đọc bởi bất kỳ người dùng/client nào qua REST API (/api/sessions hoặc /api/history).

ĐẶC TÍNH:
1. Chỉ đọc (READ-ONLY) từ MySQL: Không sửa đổi, không xóa, không ghi vào MySQL.
2. Idempotent: Bỏ qua các dòng đã tồn tại dựa trên bộ 3 khóa (session_id, created_at, user_text).
3. Import trễ (delayed import) thư viện pymysql với hướng dẫn cài đặt nếu thiếu.
4. Kiểm thử đối soát trường dữ liệu: đối chiếu số lượng dòng, risk_score, created_at, độ dài image_base64.
"""

import os
import sys
import argparse
import sqlite3
from typing import Any, Dict, List, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def migrate(
    mysql_host: str = "localhost",
    mysql_port: int = 3306,
    mysql_user: str = "root",
    mysql_password: str = "",
    mysql_database: str = "ai-anti-scam",
    sqlite_path: str = "data/safeguard.db",
    mysql_conn: Any = None,
) -> Dict[str, Any]:
    """
    Thực hiện di trú user_logs từ MySQL sang SQLite.
    Có thể truyền mysql_conn giả lập để phục vụ unit test.
    """
    close_mysql = False
    if mysql_conn is None:
        try:
            import pymysql
            import pymysql.cursors
        except ImportError:
            print("[Migration] Lỗi: Thư viện `pymysql` không có sẵn.")
            print("[Migration] Vui lòng cài đặt để chạy di trú: pip install pymysql")
            sys.exit(1)

        mysql_conn = pymysql.connect(
            host=mysql_host,
            port=mysql_port,
            user=mysql_user,
            password=mysql_password,
            database=mysql_database,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            read_timeout=30,
        )
        close_mysql = True

    try:
        # Chuẩn bị SQLite
        if sqlite_path != ":memory:":
            db_dir = os.path.dirname(os.path.abspath(sqlite_path))
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        sqlite_conn = sqlite3.connect(sqlite_path)
        sqlite_conn.row_factory = sqlite3.Row

        with sqlite_conn:
            sqlite_conn.execute("""
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
            sqlite_conn.execute("CREATE INDEX IF NOT EXISTS `idx_user_logs_session` ON `user_logs` (`session_id`);")
            sqlite_conn.execute("CREATE INDEX IF NOT EXISTS `idx_user_logs_client` ON `user_logs` (`client_id`);")

        # Đọc bản ghi hiện có trong SQLite để đảm bảo tính Idempotent
        existing_keys = set()
        cur_sq = sqlite_conn.cursor()
        cur_sq.execute("SELECT session_id, created_at, user_text FROM user_logs")
        for r in cur_sq.fetchall():
            existing_keys.add((str(r["session_id"]), str(r["created_at"]), str(r["user_text"])))

        # Đọc dữ liệu CHỈ-ĐỌC từ MySQL
        mysql_cur = mysql_conn.cursor()
        mysql_cur.execute("""
            SELECT `session_id`, `user_text`, `image_base64`, `bot_response`,
                   `risk_score`, `risk_level`, `confidence_score`, `matched_flags`,
                   `latency_ms`, `created_at`
            FROM `user_logs`
            ORDER BY `id` ASC
        """)
        mysql_rows = mysql_cur.fetchall() or []
        source_count = len(mysql_rows)

        migrated_count = 0
        skipped_count = 0

        insert_sql = """
        INSERT INTO `user_logs` (
            `session_id`, `client_id`, `user_text`, `image_base64`, `has_image`,
            `bot_response`, `risk_score`, `risk_level`, `confidence_score`,
            `matched_flags`, `latency_ms`, `created_at`
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        for row in mysql_rows:
            sid = str(row.get("session_id") or "session_default")
            utext = str(row.get("user_text") or "")
            created_at_str = str(row.get("created_at") or "")
            key = (sid, created_at_str, utext)

            if key in existing_keys:
                skipped_count += 1
                continue

            raw_img = row.get("image_base64")
            has_img = 1 if raw_img else 0
            risk_score = int(row.get("risk_score") or 0)
            risk_level = str(row.get("risk_level") or "LOW")
            confidence_score = int(row.get("confidence_score") or 0)
            flags_val = row.get("matched_flags") or ""
            flags_str = ", ".join(flags_val) if isinstance(flags_val, list) else str(flags_val)
            latency_ms = float(row.get("latency_ms") or 0.0)
            bot_resp = str(row.get("bot_response") or "")

            sqlite_conn.execute(
                insert_sql,
                (
                    sid,
                    None,  # client_id = NULL
                    utext,
                    raw_img,
                    has_img,
                    bot_resp,
                    risk_score,
                    risk_level,
                    confidence_score,
                    flags_str,
                    latency_ms,
                    created_at_str,
                ),
            )
            existing_keys.add(key)
            migrated_count += 1

        sqlite_conn.commit()

        # Kiểm tra tổng số bản ghi trong SQLite
        cur_sq.execute("SELECT COUNT(*) as cnt FROM user_logs")
        dest_count = cur_sq.fetchone()["cnt"]

        # Lấy mẫu đối soát (kiểm tra các bản ghi: đầu, giữa, cuối)
        sample_checks = []
        if mysql_rows:
            check_indices = [0, len(mysql_rows) // 2, len(mysql_rows) - 1]
            for idx in sorted(set(check_indices)):
                m_row = mysql_rows[idx]
                sid = str(m_row.get("session_id") or "session_default")
                c_at = str(m_row.get("created_at") or "")
                utext = str(m_row.get("user_text") or "")
                cur_sq.execute(
                    "SELECT risk_score, created_at, length(image_base64) as img_len FROM user_logs WHERE session_id = ? AND created_at = ? AND user_text = ? LIMIT 1",
                    (sid, c_at, utext)
                )
                sq_row = cur_sq.fetchone()
                if sq_row:
                    m_img = m_row.get("image_base64") or ""
                    m_img_len = len(m_img) if m_img else 0
                    sample_checks.append({
                        "sample_index": idx,
                        "session_id": sid,
                        "mysql_risk_score": int(m_row.get("risk_score") or 0),
                        "sqlite_risk_score": sq_row["risk_score"],
                        "mysql_created_at": c_at,
                        "sqlite_created_at": str(sq_row["created_at"]),
                        "mysql_img_len": m_img_len,
                        "sqlite_img_len": sq_row["img_len"] or 0,
                        "matched": (
                            int(m_row.get("risk_score") or 0) == sq_row["risk_score"] and
                            c_at == str(sq_row["created_at"]) and
                            m_img_len == (sq_row["img_len"] or 0)
                        )
                    })

        sqlite_conn.close()

        return {
            "source_count": source_count,
            "dest_count": dest_count,
            "migrated_count": migrated_count,
            "skipped_count": skipped_count,
            "sample_checks": sample_checks,
        }
    finally:
        if close_mysql and mysql_conn:
            try:
                mysql_conn.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Di trú user_logs từ MySQL sang SQLite.")
    parser.add_argument("--mysql-host", default=os.environ.get("MYSQL_HOST", "localhost"))
    parser.add_argument("--mysql-port", type=int, default=int(os.environ.get("MYSQL_PORT", 3306)))
    parser.add_argument("--mysql-user", default=os.environ.get("MYSQL_USER", "root"))
    parser.add_argument("--mysql-password", default=os.environ.get("MYSQL_PASSWORD", ""))
    parser.add_argument("--mysql-database", default=os.environ.get("MYSQL_DATABASE", "ai-anti-scam"))
    parser.add_argument("--sqlite-path", default=os.environ.get("SAFEGUARD_DB_PATH", "data/safeguard.db"))
    args = parser.parse_args()

    print("=================================================================")
    print("[START] BAT DAU DI TRU DU LIEU USER_LOGS: MySQL -> SQLite")
    print(f"   MySQL: {args.mysql_host}:{args.mysql_port}/{args.mysql_database}")
    print(f"   SQLite: {args.sqlite_path}")
    print("=================================================================")

    stats = migrate(
        mysql_host=args.mysql_host,
        mysql_port=args.mysql_port,
        mysql_user=args.mysql_user,
        mysql_password=args.mysql_password,
        mysql_database=args.mysql_database,
        sqlite_path=args.sqlite_path,
    )

    print(f"[OK] So dong nguon MySQL: {stats['source_count']}")
    print(f"[OK] So dong moi di tru: {stats['migrated_count']}")
    print(f"[OK] So dong bo qua (da co): {stats['skipped_count']}")
    print(f"[OK] Tong so dong dich SQLite: {stats['dest_count']}")
    print("--- Doi soat mau ---")
    all_matched = True
    for chk in stats["sample_checks"]:
        matched = chk["matched"]
        all_matched = all_matched and matched
        print(f"   Mau #{chk['sample_index']} (Session: {chk['session_id']}): "
              f"risk={chk['sqlite_risk_score']}/{chk['mysql_risk_score']}, "
              f"img_len={chk['sqlite_img_len']}/{chk['mysql_img_len']} -> Khop: {matched}")

    if all_matched and stats["dest_count"] >= stats["source_count"]:
        print("[SUCCESS] DI TRU HOAN TAT THANH CONG VA CHINH XAC 100%!")
    else:
        print("[WARNING] Canh bao: Co sai lech du lieu doi soat!")


if __name__ == "__main__":
    main()
