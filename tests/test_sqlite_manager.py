import os
import time
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest

from codebase.knowledge_base.db_connect import SQLiteManager, _mask_client_id
from codebase.config import get_settings


def test_client_write_and_read_history(tmp_path):
    """1. Ghi và đọc lịch sử theo client_id chính xác."""
    db_file = str(tmp_path / "test_history.db")
    mgr = SQLiteManager(db_path=db_file, force=True)
    client_id = "client_alice_12345678"

    ok1 = mgr.log_user_analysis(
        user_text="Kiểm tra tin nhắn tuyển dụng",
        risk_score=75,
        risk_level="HIGH",
        confidence_score=92,
        matched_flags=["tuyển dụng", "cọc tiền"],
        latency_ms=18.5,
        session_id="sess_alice_1",
        bot_response="Cảnh báo lừa đảo",
        client_id=client_id,
    )
    assert ok1 is True

    ok2 = mgr.log_user_analysis(
        user_text="Kiểm tra tin thứ 2",
        risk_score=20,
        risk_level="LOW",
        confidence_score=85,
        matched_flags=[],
        latency_ms=10.0,
        session_id="sess_alice_1",
        bot_response="An toàn",
        client_id=client_id,
    )
    assert ok2 is True

    # Đọc lại lịch sử của sess_alice_1
    history = mgr.get_chat_history("sess_alice_1", client_id=client_id)
    assert len(history) == 2
    assert history[0]["user_text"] == "Kiểm tra tin nhắn tuyển dụng"
    assert history[0]["risk_score"] == 75
    assert history[0]["risk_level"] == "HIGH"
    assert history[1]["user_text"] == "Kiểm tra tin thứ 2"
    assert history[1]["risk_score"] == 20

    # Đọc danh sách session
    sessions = mgr.get_all_sessions(client_id=client_id)
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == "sess_alice_1"
    assert sessions[0]["msg_count"] == 2

    mgr.close()


def test_client_a_cannot_read_client_b(tmp_path):
    """2. Client A không thể đọc dữ liệu của Client B (cô lập dữ liệu)."""
    db_file = str(tmp_path / "test_cross_client.db")
    mgr = SQLiteManager(db_path=db_file, force=True)
    client_a = "client_AAAA_11111111"
    client_b = "client_BBBB_22222222"
    shared_session = "sess_secret_collab"

    mgr.log_user_analysis(
        user_text="Mã OTP bảo mật của Client A: 998877",
        risk_score=10,
        risk_level="LOW",
        confidence_score=95,
        matched_flags=[],
        latency_ms=5.0,
        session_id=shared_session,
        client_id=client_a,
    )

    # Client B cố đọc lịch sử session này
    b_history = mgr.get_chat_history(shared_session, client_id=client_b)
    assert len(b_history) == 0, "Client B không được đọc lịch sử của Client A"

    # Client B cố đọc danh sách sessions
    b_sessions = mgr.get_all_sessions(client_id=client_b)
    assert len(b_sessions) == 0, "Client B không được nhìn thấy session của Client A"

    # Client A đọc thì thấy
    a_history = mgr.get_chat_history(shared_session, client_id=client_a)
    assert len(a_history) == 1
    assert "998877" in a_history[0]["user_text"]

    mgr.close()


def test_anonymous_null_cannot_be_read_by_any_client(tmp_path):
    """3. Bản ghi ẩn danh (client_id=None) được lưu NULL và không client nào đọc được."""
    db_file = str(tmp_path / "test_anon.db")
    mgr = SQLiteManager(db_path=db_file, force=True)

    # Log với client_id bắt đầu bằng anonymous-
    mgr.log_user_analysis(
        user_text="Tin nhắn người dùng ẩn danh",
        risk_score=30,
        risk_level="LOW",
        confidence_score=80,
        matched_flags=[],
        latency_ms=8.0,
        session_id="sess_anon_1",
        client_id="anonymous-a1b2c3d4e5f60718",
    )

    # Kiểm tra trực tiếp trong DB: client_id phải là NULL
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("SELECT client_id FROM user_logs WHERE session_id = 'sess_anon_1'")
    row = cur.fetchone()
    assert row is not None
    assert row[0] is None, f"Bản ghi ẩn danh phải lưu client_id = NULL, nhưng là {row[0]}"
    conn.close()

    # Bất kỳ client nào gọi API đều không lấy được bản ghi này
    for test_cid in ("client_user_1", "client_user_2", "anonymous-a1b2c3d4e5f60718"):
        history = mgr.get_chat_history("sess_anon_1", client_id=test_cid)
        assert len(history) == 0

        sessions = mgr.get_all_sessions(client_id=test_cid)
        assert len(sessions) == 0

    mgr.close()


def test_client_id_case_sensitive_binary_collation(tmp_path):
    """4. So sánh client_id phải phân biệt hoa/thường (BINARY/COLLATE BINARY)."""
    db_file = str(tmp_path / "test_collation.db")
    mgr = SQLiteManager(db_path=db_file, force=True)

    client_lower = "client_token_xyz"
    client_upper = "CLIENT_TOKEN_XYZ"
    client_mixed = "Client_Token_Xyz"

    mgr.log_user_analysis(
        user_text="Data của lowercase",
        risk_score=10,
        risk_level="LOW",
        confidence_score=90,
        matched_flags=[],
        latency_ms=5.0,
        session_id="s_case",
        client_id=client_lower,
    )

    mgr.log_user_analysis(
        user_text="Data của UPPERCASE",
        risk_score=90,
        risk_level="HIGH",
        confidence_score=95,
        matched_flags=[],
        latency_ms=5.0,
        session_id="s_case",
        client_id=client_upper,
    )

    # Truy vấn với lower -> CHỈ ra bản ghi lower
    hist_lower = mgr.get_chat_history("s_case", client_id=client_lower)
    assert len(hist_lower) == 1
    assert hist_lower[0]["user_text"] == "Data của lowercase"

    # Truy vấn với upper -> CHỈ ra bản ghi upper
    hist_upper = mgr.get_chat_history("s_case", client_id=client_upper)
    assert len(hist_upper) == 1
    assert hist_upper[0]["user_text"] == "Data của UPPERCASE"

    # Truy vấn với mixed case -> không ra bản ghi nào
    hist_mixed = mgr.get_chat_history("s_case", client_id=client_mixed)
    assert len(hist_mixed) == 0

    mgr.close()


def test_lock_timeout_fail_open(tmp_path, monkeypatch):
    """5. Khóa nội bộ (_lock) timeout phải fail-open trong <= db_timeout_s + 0.5s."""
    monkeypatch.setenv("SAFEGUARD_DB_TIMEOUT", "0.3")
    get_settings(refresh=True)

    try:
        db_file = str(tmp_path / "test_lock.db")
        mgr = SQLiteManager(db_path=db_file, force=True)

        # Giữ khóa _lock để giả lập luồng khác đang kẹt
        mgr._lock.acquire()

        t0 = time.monotonic()
        res = mgr.log_user_analysis(
            user_text="Test timeout",
            risk_score=10,
            risk_level="LOW",
            confidence_score=90,
            matched_flags=[],
            latency_ms=5.0,
            session_id="s_lock"
        )
        elapsed = time.monotonic() - t0

        db_to = getattr(get_settings(), "db_timeout_s", 1.0)
        assert res is False, "Khi timeout khóa, hàm phải trả về False (fail-open)"
        assert elapsed <= db_to + 0.5, f"Quá thời gian timeout: {elapsed:.2f}s > {db_to + 0.5}s"

        # Giải phóng khóa và gọi lại -> phải thành công
        mgr._lock.release()
        res_ok = mgr.log_user_analysis(
            user_text="Test sau giải phóng",
            risk_score=10,
            risk_level="LOW",
            confidence_score=90,
            matched_flags=[],
            latency_ms=5.0,
            session_id="s_lock"
        )
        assert res_ok is True
        mgr.close()
    finally:
        monkeypatch.undo()
        get_settings(refresh=True)


def test_db_locked_by_another_connection_fail_open(tmp_path, monkeypatch):
    """6. File DB bị khóa bởi kết nối khác (BEGIN EXCLUSIVE) => fail-open trong <= db_timeout_s + 0.5s."""
    db_file = str(tmp_path / "exclusive_locked.db")
    monkeypatch.setenv("SAFEGUARD_DB_TIMEOUT", "1.0")
    get_settings(refresh=True)

    try:
        # Khởi tạo bảng trước
        init_mgr = SQLiteManager(db_path=db_file, force=True)
        init_mgr.close()

        # Kết nối 1: chiếm khóa độc quyền BEGIN EXCLUSIVE
        conn1 = sqlite3.connect(db_file, timeout=1.0)
        conn1.execute("BEGIN EXCLUSIVE")

        # Kết nối 2 (SQLiteManager): cố ghi vào DB đang bị khóa
        mgr2 = SQLiteManager(db_path=db_file, force=True)

        t0 = time.monotonic()
        res = mgr2.log_user_analysis(
            user_text="Tin nhắn khi DB bị khóa",
            risk_score=50,
            risk_level="MEDIUM",
            confidence_score=80,
            matched_flags=[],
            latency_ms=10.0,
            session_id="s_ex"
        )
        elapsed = time.monotonic() - t0

        db_to = getattr(get_settings(), "db_timeout_s", 1.0)
        assert res is False, "Phải fail-open trả về False khi SQLite OperationalError locked"
        assert elapsed <= db_to + 0.5, f"Thời gian chờ quá lâu: {elapsed:.2f}s (kỳ vọng <= {db_to + 0.5}s)"

        # Kết nối 1 giải phóng khóa
        conn1.rollback()
        conn1.close()

        # Thử lại sau khi giải phóng -> ghi thành công
        res2 = mgr2.log_user_analysis(
            user_text="Tin nhắn sau khi mở khóa",
            risk_score=10,
            risk_level="LOW",
            confidence_score=90,
            matched_flags=[],
            latency_ms=5.0,
            session_id="s_ex"
        )
        assert res2 is True
        mgr2.close()
    finally:
        monkeypatch.undo()
        get_settings(refresh=True)


def test_concurrent_multithreaded_writes_no_errors(tmp_path):
    """7. Nhiều luồng ghi song song vào SQLite không bị lỗi hoặc deadlock."""
    db_file = str(tmp_path / "concurrent.db")
    mgr = SQLiteManager(db_path=db_file, force=True)

    num_threads = 8
    writes_per_thread = 10
    total_writes = num_threads * writes_per_thread

    def worker(tid: int):
        results = []
        for i in range(writes_per_thread):
            ok = mgr.log_user_analysis(
                user_text=f"Thread {tid} message {i}",
                risk_score=20,
                risk_level="LOW",
                confidence_score=85,
                matched_flags=[],
                latency_ms=2.0,
                session_id=f"sess_t_{tid}",
                client_id=f"client_t_{tid}"
            )
            results.append(ok)
        return results

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, t) for t in range(num_threads)]
        all_results = [res for f in futures for res in f.result()]

    assert len(all_results) == total_writes
    assert all(r is True for r in all_results), "Tất cả các lượt ghi đồng thời phải thành công"

    # Kiểm tra tổng số bản ghi trong DB
    conn = sqlite3.connect(db_file)
    count = conn.execute("SELECT COUNT(*) FROM user_logs").fetchone()[0]
    conn.close()
    assert count == total_writes
    mgr.close()


def test_store_images_setting_behavior(tmp_path, monkeypatch):
    """8. store_images=False không lưu base64 ảnh; store_images=True lưu đầy đủ."""
    db_file = str(tmp_path / "test_img.db")
    raw_img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"

    # 1. Khi store_images = False (mặc định)
    monkeypatch.setenv("SAFEGUARD_STORE_IMAGES", "0")
    get_settings(refresh=True)

    mgr = SQLiteManager(db_path=db_file, force=True)
    mgr.log_user_analysis(
        user_text="User gửi bill ảnh 1",
        risk_score=60,
        risk_level="MEDIUM",
        confidence_score=88,
        matched_flags=["bill"],
        latency_ms=25.0,
        session_id="s_img_off",
        image_base64=raw_img,
        client_id="c_img_1"
    )

    # Kiểm tra trực tiếp trong DB: image_base64 phải là None, has_image = 1
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    row1 = conn.execute("SELECT * FROM user_logs WHERE session_id = 's_img_off'").fetchone()
    assert row1["image_base64"] is None, "Không được lưu base64 ảnh vào DB khi store_images=False"
    assert row1["has_image"] == 1, "has_image phải là 1 khi người dùng có gửi ảnh"

    # Đọc qua get_chat_history: image_base64 trả về chuỗi rỗng "", has_image=True
    hist1 = mgr.get_chat_history("s_img_off", client_id="c_img_1")
    assert hist1[0]["has_image"] is True
    assert hist1[0]["image_base64"] == ""

    # 2. Khi store_images = True
    monkeypatch.setenv("SAFEGUARD_STORE_IMAGES", "1")
    get_settings(refresh=True)

    mgr.log_user_analysis(
        user_text="User gửi bill ảnh 2",
        risk_score=60,
        risk_level="MEDIUM",
        confidence_score=88,
        matched_flags=["bill"],
        latency_ms=25.0,
        session_id="s_img_on",
        image_base64=raw_img,
        client_id="c_img_2"
    )

    row2 = conn.execute("SELECT * FROM user_logs WHERE session_id = 's_img_on'").fetchone()
    assert row2["image_base64"] == raw_img, "Phải lưu base64 ảnh khi store_images=True"
    assert row2["has_image"] == 1

    hist2 = mgr.get_chat_history("s_img_on", client_id="c_img_2")
    assert hist2[0]["has_image"] is True
    assert hist2[0]["image_base64"] == raw_img

    conn.close()
    mgr.close()
    monkeypatch.undo()
    get_settings(refresh=True)
