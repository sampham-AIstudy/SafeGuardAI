import os
import sqlite3
import pytest
from unittest.mock import MagicMock
from scripts.migrate_mysql_to_sqlite import migrate


def test_migrate_mysql_to_sqlite_idempotent_and_client_id_null(tmp_path):
    """
    Test that migration copies rows from MySQL to SQLite:
    1. Sets client_id = NULL for security isolation.
    2. Correctly copies risk_score, latency_ms, image_base64, has_image.
    3. Is strictly idempotent (second run skips existing rows).
    """
    db_file = str(tmp_path / "test_migrated.db")

    fake_mysql_rows = [
        {
            "session_id": "sess_1",
            "user_text": "Tin nhắn kiểm tra 1",
            "image_base64": None,
            "bot_response": "Phản hồi bot 1",
            "risk_score": 15,
            "risk_level": "LOW",
            "confidence_score": 90,
            "matched_flags": ["tactic_1"],
            "latency_ms": 12.5,
            "created_at": "2026-10-18 10:00:00",
        },
        {
            "session_id": "sess_2",
            "user_text": "Tin nhắn lừa đảo 2",
            "image_base64": "data:image/png;base64,aGVsbG8=",
            "bot_response": "Cảnh báo lừa đảo",
            "risk_score": 95,
            "risk_level": "HIGH",
            "confidence_score": 98,
            "matched_flags": "tactic_2, tactic_3",
            "latency_ms": 45.0,
            "created_at": "2026-10-18 10:05:00",
        },
    ]

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = fake_mysql_rows

    # First migration run
    res1 = migrate(sqlite_path=db_file, mysql_conn=mock_conn)
    assert res1["source_count"] == 2
    assert res1["migrated_count"] == 2
    assert res1["skipped_count"] == 0
    assert res1["dest_count"] == 2
    assert len(res1["sample_checks"]) > 0
    for chk in res1["sample_checks"]:
        assert chk["matched"] is True

    # Verify rows in SQLite
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM user_logs ORDER BY id ASC").fetchall()
    assert len(rows) == 2

    # client_id must be NULL
    assert rows[0]["client_id"] is None
    assert rows[1]["client_id"] is None

    # First row has no image
    assert rows[0]["has_image"] == 0
    assert rows[0]["image_base64"] is None
    assert rows[0]["risk_score"] == 15

    # Second row has image
    assert rows[1]["has_image"] == 1
    assert rows[1]["image_base64"] == "data:image/png;base64,aGVsbG8="
    assert rows[1]["risk_score"] == 95
    conn.close()

    # Second migration run: must skip existing rows
    res2 = migrate(sqlite_path=db_file, mysql_conn=mock_conn)
    assert res2["source_count"] == 2
    assert res2["migrated_count"] == 0
    assert res2["skipped_count"] == 2
    assert res2["dest_count"] == 2
