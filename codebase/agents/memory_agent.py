import re
import threading
from collections import OrderedDict, deque


class MemoryAgent:
    """
    Memory Agent:
    Maintains interaction history across multi-turn / multi-day conversations
    to detect escalating sequential scam patterns (e.g. Day 1 -> Day 3 -> Day 5).
    Thread-safe, session-isolated, with bounded session count (LRU) and deque maxlen.
    """
    def __init__(self, max_history: int = 20, max_sessions: int = 1000):
        self._max_history = max_history
        self._max_sessions = max_sessions
        self._lock = threading.Lock()
        self._sessions = OrderedDict()  # session_id -> deque(maxlen=20)
        self._vi_recruitment_regex = re.compile(
            r"(?<!\w)(?:việc làm|nhận việc|tuyển dụng|cộng tác viên|làm thêm)(?!\w)", re.IGNORECASE
        )

    def _make_key(self, session_id: str, client_id: str | None = None):
        if client_id is not None:
            return (client_id, session_id)
        return session_id

    def _get_session_deque(self, session_id: str, client_id: str | None = None, create: bool = True) -> deque:
        # Caller must hold self._lock
        key = self._make_key(session_id, client_id)
        if key in self._sessions:
            self._sessions.move_to_end(key)
            return self._sessions[key]
        if not create:
            return deque(maxlen=self._max_history)
        if len(self._sessions) >= self._max_sessions:
            self._sessions.popitem(last=False)
        d = deque(maxlen=self._max_history)
        self._sessions[key] = d
        return d

    @property
    def history(self):
        with self._lock:
            if "session_default" not in self._sessions:
                if len(self._sessions) >= self._max_sessions:
                    self._sessions.popitem(last=False)
                self._sessions["session_default"] = deque(maxlen=self._max_history)
            return self._sessions["session_default"]

    @history.setter
    def history(self, value):
        with self._lock:
            if "session_default" not in self._sessions and len(self._sessions) >= self._max_sessions:
                self._sessions.popitem(last=False)
            self._sessions["session_default"] = deque(value or [], maxlen=self._max_history)
            self._sessions.move_to_end("session_default")

    def reset(self, session_id: str = None, client_id: str = None):
        """
        Reset interaction history.
        If session_id and client_id are both None, clears all sessions.
        If client_id is provided and session_id is None, clears all sessions for that client.
        If session_id is provided, clears only that session for the given client (or legacy session_id).
        """
        with self._lock:
            if session_id is None and client_id is None:
                self._sessions.clear()
            elif session_id is None and client_id is not None:
                to_del = [k for k in self._sessions if isinstance(k, tuple) and k[0] == client_id]
                for k in to_del:
                    self._sessions.pop(k, None)
            else:
                key = self._make_key(session_id, client_id)
                self._sessions.pop(key, None)

    def add_interaction(self, user_text, risk_level, matched_flags, session_id: str = "session_default", client_id: str = None):
        with self._lock:
            dq = self._get_session_deque(session_id, client_id=client_id, create=True)
            dq.append({
                "text": user_text,
                "risk_level": risk_level,
                "flags": matched_flags
            })

    def load_history_from_db(self, db_manager, session_id: str = "session_default", client_id: str = None):
        """Loads interaction history from MySQL database for a specific session and client."""
        if not db_manager or not db_manager.is_connected:
            return
        db_history = db_manager.get_chat_history(session_id, client_id=client_id)
        if db_history:
            with self._lock:
                dq = self._get_session_deque(session_id, client_id=client_id, create=True)
                dq.clear()
                for row in db_history:
                    flags = []
                    user_text = row.get("user_text", "")
                    risk_level = row.get("risk_level", "LOW")
                    dq.append({
                        "text": user_text,
                        "risk_level": risk_level,
                        "flags": flags
                    })
                count = len(dq)
            print(f"[MemoryAgent] Successfully loaded {count} historical records from MySQL for session `{session_id}` (client={client_id}).")

    def analyze_escalation(self, current_text, session_id: str = "session_default", client_id: str = None):
        key = self._make_key(session_id, client_id)
        with self._lock:
            if key not in self._sessions:
                hist_snapshot = []
            else:
                self._sessions.move_to_end(key)
                hist_snapshot = list(self._sessions[key])

        escalation_detected = False
        escalation_reason = ""
        all_flags = []

        for item in hist_snapshot:
            all_flags.extend(item.get("flags", []))

        # Example escalation: Job post -> Transfer money / deposit
        has_recruitment = any(
            bool(self._vi_recruitment_regex.search(item.get("text", "")))
            for item in hist_snapshot
        )
        current_has_transfer = any(
            w in (current_text or "").lower()
            for w in ["chuyển tiền", "nạp", "500k", "quỹ", "cọc", "bill"]
        )

        if has_recruitment and current_has_transfer:
            escalation_detected = True
            escalation_reason = "Phát hiện chuỗi lừa đảo leo thang (Sequential Scam Pattern): Từ tuyển dụng việc làm $\\rightarrow$ Yêu cầu nạp tiền/chuyển khoản."

        return {
            "history_count": len(hist_snapshot),
            "escalation_detected": escalation_detected,
            "escalation_reason": escalation_reason,
            "accumulated_flags": list(set(all_flags))
        }


if __name__ == "__main__":
    mem = MemoryAgent()
    mem.add_interaction("Anh ơi em tìm được việc làm tuyển dụng xem TikTok 500k/ngày", "LOW", ["tuyển dụng"])
    res = mem.analyze_escalation("Họ bảo em phải chuyển 500k cọc quỹ đảm bảo mới cho nhận việc")
    print("[MemoryAgent] Escalation Result:", res)

