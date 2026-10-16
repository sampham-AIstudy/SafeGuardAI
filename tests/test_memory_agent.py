import concurrent.futures
import threading
from codebase.agents.memory_agent import MemoryAgent


def test_session_isolation_no_leak():
    """Session A talking about recruitment should not cause Session B to trigger escalation."""
    mem = MemoryAgent()
    # Session A records recruitment interaction
    mem.add_interaction(
        user_text="Em tìm việc làm tuyển dụng CTV xem video 500k/ngày",
        risk_level="LOW",
        matched_flags=["tuyển dụng"],
        session_id="session_A"
    )

    # Session B checks escalation with transfer message
    res_b = mem.analyze_escalation(
        current_text="Tôi chuyển 500k tiền học phí cho con nhé",
        session_id="session_B"
    )
    assert not res_b["escalation_detected"], "Session B must not detect escalation from Session A's history"
    assert res_b["history_count"] == 0

    # Session A checks escalation with transfer message -> should trigger
    res_a = mem.analyze_escalation(
        current_text="Họ yêu cầu nạp tiền 500k quỹ cọc",
        session_id="session_A"
    )
    assert res_a["escalation_detected"], "Session A must detect escalation when recruitment is followed by deposit"
    assert res_a["history_count"] == 1


def test_concurrent_threads_no_crash():
    """Multiple threads accessing memory agent simultaneously must not crash or race."""
    mem = MemoryAgent()
    num_threads = 10
    iterations_per_thread = 50

    def worker(thread_idx):
        sid = f"thread_session_{thread_idx}"
        for i in range(iterations_per_thread):
            mem.add_interaction(f"tin nhắn {i} tuyển dụng", "LOW", ["flag"], session_id=sid)
            res = mem.analyze_escalation("yêu cầu nạp 500k", session_id=sid)
            assert res["history_count"] > 0
            if i % 10 == 0:
                mem.reset(sid)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            f.result()  # Re-raise any exception


def test_session_limit_lru_eviction():
    """Exceeding max_sessions must evict the least recently used session."""
    mem = MemoryAgent(max_history=5, max_sessions=3)
    # Add 3 sessions
    mem.add_interaction("msg 1", "LOW", [], session_id="s1")
    mem.add_interaction("msg 2", "LOW", [], session_id="s2")
    mem.add_interaction("msg 3", "LOW", [], session_id="s3")

    assert len(mem._sessions) == 3
    assert "s1" in mem._sessions
    assert "s2" in mem._sessions
    assert "s3" in mem._sessions

    # Access s1 so s2 becomes LRU
    mem.analyze_escalation("check", session_id="s1")

    # Add 4th session -> s2 should be evicted
    mem.add_interaction("msg 4", "LOW", [], session_id="s4")

    assert len(mem._sessions) == 3
    assert "s1" in mem._sessions
    assert "s2" not in mem._sessions, "s2 should have been evicted as LRU"
    assert "s3" in mem._sessions
    assert "s4" in mem._sessions


def test_history_compatibility():
    """Verify legacy .history property behavior for backward compatibility."""
    mem = MemoryAgent()
    # Reading empty history
    assert len(mem.history) == 0

    # Appending directly to history
    mem.history.append({"text": "tin tuyển dụng việc làm", "risk_level": "LOW", "flags": []})
    assert len(mem.history) == 1
    assert mem.analyze_escalation("nạp tiền", session_id="session_default")["escalation_detected"]

    # Setter
    mem.history = [{"text": "custom", "risk_level": "HIGH", "flags": ["custom_flag"]}]
    assert len(mem.history) == 1
    assert mem.history[0]["text"] == "custom"

    # Clearing history
    mem.history.clear()
    assert len(mem.history) == 0


def test_reset_behavior():
    """Verify reset() for specific session vs all sessions."""
    mem = MemoryAgent()
    mem.add_interaction("text 1", "LOW", [], session_id="sess_1")
    mem.add_interaction("text 2", "LOW", [], session_id="sess_2")

    assert len(mem._sessions) == 2

    # Reset single session
    mem.reset("sess_1")
    assert "sess_1" not in mem._sessions
    assert "sess_2" in mem._sessions

    # Reset all sessions
    mem.reset()
    assert len(mem._sessions) == 0


def test_word_boundary_for_viec():
    """'việc' must match with word boundaries and not match arbitrary substrings."""
    mem = MemoryAgent()
    # Substring without word boundary should not trigger recruitment
    mem.add_interaction("abcviệcxyz", "LOW", [], session_id="s_bound")
    res1 = mem.analyze_escalation("nạp tiền 500k", session_id="s_bound")
    assert not res1["escalation_detected"]

    # Word boundary should trigger recruitment
    mem.reset()
    mem.add_interaction("tìm việc làm thêm", "LOW", [], session_id="s_bound")
    res2 = mem.analyze_escalation("nạp tiền 500k", session_id="s_bound")
    assert res2["escalation_detected"]


def test_history_getter_does_not_alter_lru_order():
    """Accessing .history getter must NOT move session_default to the end of LRU."""
    mem = MemoryAgent(max_sessions=3)
    mem.add_interaction("msg 1", "LOW", [], session_id="session_default")
    mem.add_interaction("msg 2", "LOW", [], session_id="s2")
    mem.add_interaction("msg 3", "LOW", [], session_id="s3")

    # Order of keys in _sessions: 'session_default' (oldest), 's2', 's3' (newest)
    # Accessing .history getter should NOT move session_default to the end!
    _ = mem.history

    # Adding s4 should evict 'session_default' as the true LRU
    mem.add_interaction("msg 4", "LOW", [], session_id="s4")
    assert "session_default" not in mem._sessions
    assert "s2" in mem._sessions
    assert "s3" in mem._sessions
    assert "s4" in mem._sessions


def test_history_setter_respects_max_sessions_lru():
    """Assigning to .history setter must respect max_sessions limit and evict LRU."""
    mem = MemoryAgent(max_sessions=3)
    mem.add_interaction("msg 1", "LOW", [], session_id="s1")
    mem.add_interaction("msg 2", "LOW", [], session_id="s2")
    mem.add_interaction("msg 3", "LOW", [], session_id="s3")
    assert len(mem._sessions) == 3

    # Setting .history when session_default is not in _sessions must evict s1 (oldest)
    mem.history = [{"text": "new", "risk_level": "LOW", "flags": []}]
    assert len(mem._sessions) == 3
    assert "s1" not in mem._sessions
    assert "s2" in mem._sessions
    assert "s3" in mem._sessions
    assert "session_default" in mem._sessions


def test_recruitment_regex_precision():
    """Only 'việc làm|nhận việc|tuyển dụng|cộng tác viên|làm thêm' can trigger recruitment escalation."""
    mem = MemoryAgent()
    # 'chuyện công việc gia đình' + 'nạp 500k vào quỹ' must NOT escalate
    mem.add_interaction("chuyện công việc gia đình", "LOW", [], session_id="s_benign_job")
    res1 = mem.analyze_escalation("nạp 500k vào quỹ", session_id="s_benign_job")
    assert not res1["escalation_detected"], "'công việc gia đình' must not trigger recruitment escalation"

    # 'tuyển cộng tác viên' + 'nạp 500k nhận nhiệm vụ' must escalate
    mem.add_interaction("tuyển cộng tác viên", "LOW", [], session_id="s_scam_job")
    res2 = mem.analyze_escalation("nạp 500k nhận nhiệm vụ", session_id="s_scam_job")
    assert res2["escalation_detected"], "'tuyển cộng tác viên' followed by 500k must trigger escalation"


def test_concurrent_threads_memory_agent_lock_stress():
    """Stress test with 32 threads x 500 iterations (>= 0.5s); fails if Lock is removed."""
    import time
    mem = MemoryAgent(max_history=20, max_sessions=100)

    class LockProxy:
        def __init__(self, real_lock):
            self._real_lock = real_lock
            self.acquire_count = 0
            self._count_lock = threading.Lock()
        def __enter__(self):
            with self._count_lock:
                self.acquire_count += 1
            return self._real_lock.__enter__()
        def __exit__(self, *args):
            return self._real_lock.__exit__(*args)

    assert hasattr(mem, "_lock") and mem._lock is not None, "MemoryAgent must have _lock attribute"
    proxy = LockProxy(mem._lock)
    mem._lock = proxy

    num_threads = 32
    iterations_per_thread = 500
    num_shared_sessions = 4

    t0 = time.perf_counter()
    errors = []

    def worker(tid):
        try:
            sid = f"shared_session_{tid % num_shared_sessions}"
            for i in range(iterations_per_thread):
                mem.add_interaction(f"msg {i} việc làm", "LOW", ["f"], session_id=sid)
                res = mem.analyze_escalation("nạp 500k", session_id=sid)
                if i % 15 == 0:
                    time.sleep(0.016)
                if i % 50 == 0:
                    _ = mem.history
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    duration = time.perf_counter() - t0
    assert not errors, f"Concurrent execution produced errors: {errors}"
    assert duration >= 0.5, f"Stress test took {duration:.2f}s (< 0.5s)"
    assert proxy.acquire_count >= 1000, f"MemoryAgent lock was not acquired during operations ({proxy.acquire_count})"
    # Check each shared session has exactly max_history entries (20)
    for i in range(num_shared_sessions):
        sid = f"shared_session_{i}"
        with mem._lock:
            dq = mem._sessions[sid]
            assert len(dq) == 20


