import re
import threading
import hashlib
from collections import OrderedDict, deque


class MemoryAgent:
    """
    Memory Agent:
    Maintains interaction history across multi-turn / multi-day conversations
    to detect escalating sequential scam patterns (e.g. Day 1 -> Day 3 -> Day 5).
    Thread-safe, client-isolated with per-client quota (max 50 sessions/client, LRU within client),
    global session ceiling (max 2000 sessions total; evict least active client),
    and per-interaction text truncation (max 2000 chars).
    """
    def __init__(
        self,
        max_history: int = 20,
        max_sessions: int = 2000,
        max_sessions_per_client: int = 50,
        max_text_chars: int = 2000,
        max_total_chars: int | None = None,
    ):
        from codebase.config import get_settings
        settings = get_settings()
        self._max_history = max_history
        self._max_global_sessions = max_sessions
        self._max_sessions_per_client = min(max_sessions_per_client, max_sessions)
        self._max_text_chars = max_text_chars
        if max_total_chars is not None:
            self._max_total_chars = max(100, int(max_total_chars))
        else:
            self._max_total_chars = getattr(settings, "max_memory_chars", 8_000_000)
        self._lock = threading.Lock()
        
        # Global session map for backward compatibility and quick lookup:
        # key -> deque(maxlen=max_history)
        self._sessions = OrderedDict()
        
        # Per-client structures for strict client quotas and LRU within client:
        # client_id -> OrderedDict of session_id -> deque(maxlen=max_history)
        self._client_sessions: dict[str, OrderedDict[str, deque]] = {}
        # Client LRU tracking: client_id -> True
        self._clients_lru = OrderedDict()

        self._vi_recruitment_regex = re.compile(
            r"(?<!\w)(?:việc làm|nhận việc|tuyển dụng|cộng tác viên|làm thêm)(?!\w)", re.IGNORECASE
        )

    def _resolve_cid(self, client_id: str | None) -> str:
        if client_id == "":
            return "__empty__"
        if client_id is not None:
            return client_id
        return "__default__"

    def _make_key(self, session_id: str, client_id: str | None = None):
        if client_id == "":
            return ("__empty__", session_id)
        if client_id is not None:
            return (client_id, session_id)
        return session_id

    def _make_key_from_cid(self, session_id: str, cid: str):
        if cid == "__default__":
            return session_id
        return (cid, session_id)

    def _evict_chars_unlocked(self, current_cid: str, incoming_chars: int):
        # Must hold self._lock
        curr_chars = 0
        for dq in self._sessions.values():
            for item in dq:
                curr_chars += len(item.get("text", ""))

        while curr_chars + incoming_chars > self._max_total_chars:
            evicted = False
            for oldest_cid in list(self._clients_lru.keys()):
                if oldest_cid != current_cid and oldest_cid in self._client_sessions and self._client_sessions[oldest_cid]:
                    old_sid, old_dq = self._client_sessions[oldest_cid].popitem(last=False)
                    old_key = self._make_key_from_cid(old_sid, oldest_cid)
                    self._sessions.pop(old_key, None)
                    for item in old_dq:
                        curr_chars -= len(item.get("text", ""))
                    if not self._client_sessions[oldest_cid]:
                        del self._client_sessions[oldest_cid]
                        self._clients_lru.pop(oldest_cid, None)
                    evicted = True
                    break
            if not evicted:
                break

    def _get_session_deque(self, session_id: str, client_id: str | None = None, create: bool = True, touch: bool = True) -> deque:
        # Caller must hold self._lock
        cid = self._resolve_cid(client_id)
        key = self._make_key(session_id, client_id)

        # 1. If session already exists for this client, mark active and return
        if cid in self._client_sessions and session_id in self._client_sessions[cid]:
            if touch:
                self._clients_lru.move_to_end(cid)
                self._client_sessions[cid].move_to_end(session_id)
                if key in self._sessions:
                    self._sessions.move_to_end(key)
            return self._client_sessions[cid][session_id]

        if not create:
            return deque(maxlen=self._max_history)

        # 2. Ensure client map exists
        if cid not in self._client_sessions:
            self._client_sessions[cid] = OrderedDict()
        if touch:
            self._clients_lru[cid] = True
            self._clients_lru.move_to_end(cid)
        else:
            self._clients_lru.setdefault(cid, True)

        client_map = self._client_sessions[cid]

        # 3. Check per-client quota (max 50 sessions per client)
        if len(client_map) >= self._max_sessions_per_client:
            evicted_sid, _ = client_map.popitem(last=False)
            evicted_key = self._make_key(evicted_sid, client_id)
            self._sessions.pop(evicted_key, None)

        # 4. Check global quota (max 2000 sessions total across all clients)
        # When full, evict from least active client (not the currently active client)
        if len(self._sessions) >= self._max_global_sessions:
            evicted = False
            for oldest_cid in list(self._clients_lru.keys()):
                if oldest_cid != cid and oldest_cid in self._client_sessions and self._client_sessions[oldest_cid]:
                    old_sid, _ = self._client_sessions[oldest_cid].popitem(last=False)
                    old_key = self._make_key_from_cid(old_sid, oldest_cid)
                    self._sessions.pop(old_key, None)
                    if not self._client_sessions[oldest_cid]:
                        del self._client_sessions[oldest_cid]
                        self._clients_lru.pop(oldest_cid, None)
                    evicted = True
                    break
            if not evicted:
                if client_map:
                    evicted_sid, _ = client_map.popitem(last=False)
                    evicted_key = self._make_key(evicted_sid, client_id)
                    self._sessions.pop(evicted_key, None)

        d = deque(maxlen=self._max_history)
        client_map[session_id] = d
        self._sessions[key] = d
        return d

    @property
    def history(self):
        with self._lock:
            return self._get_session_deque("session_default", client_id=None, create=True, touch=False)

    @history.setter
    def history(self, value):
        with self._lock:
            dq = self._get_session_deque("session_default", client_id=None, create=True)
            dq.clear()
            dq.extend(value or [])

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
                self._client_sessions.clear()
                self._clients_lru.clear()
            elif session_id is None and client_id is not None:
                cid = self._resolve_cid(client_id)
                if cid in self._client_sessions:
                    for sid in list(self._client_sessions[cid].keys()):
                        key = self._make_key(sid, client_id)
                        self._sessions.pop(key, None)
                    del self._client_sessions[cid]
                self._clients_lru.pop(cid, None)
            else:
                cid = self._resolve_cid(client_id)
                if cid in self._client_sessions:
                    self._client_sessions[cid].pop(session_id, None)
                    if not self._client_sessions[cid]:
                        del self._client_sessions[cid]
                        self._clients_lru.pop(cid, None)
                key = self._make_key(session_id, client_id)
                self._sessions.pop(key, None)

    def add_interaction(self, user_text, risk_level, matched_flags, session_id: str = "session_default", client_id: str = None):
        truncated_text = (user_text or "")[:self._max_text_chars]
        cid = self._resolve_cid(client_id)
        with self._lock:
            self._evict_chars_unlocked(cid, len(truncated_text))
            dq = self._get_session_deque(session_id, client_id=client_id, create=True)
            dq.append({
                "text": truncated_text,
                "risk_level": risk_level,
                "flags": matched_flags
            })

    def load_history_from_db(self, db_manager, session_id: str = "session_default", client_id: str = None):
        """Loads interaction history from MySQL database for a specific session and client."""
        if not db_manager or not db_manager.is_connected:
            return
        db_history = db_manager.get_chat_history(session_id, client_id=client_id)
        if db_history:
            cid = self._resolve_cid(client_id)
            total_loaded = sum(len((r.get("user_text", "") or "")[:self._max_text_chars]) for r in db_history)
            with self._lock:
                self._evict_chars_unlocked(cid, total_loaded)
                dq = self._get_session_deque(session_id, client_id=client_id, create=True)
                dq.clear()
                for row in db_history:
                    flags = []
                    user_text = (row.get("user_text", "") or "")[:self._max_text_chars]
                    risk_level = row.get("risk_level", "LOW")
                    dq.append({
                        "text": user_text,
                        "risk_level": risk_level,
                        "flags": flags
                    })
                count = len(dq)
            client_hash = hashlib.sha256(client_id.encode('utf-8')).hexdigest()[:8] if client_id else "none"
            print(f"[MemoryAgent] Successfully loaded {count} historical records from MySQL for session `{session_id}` (client_hash={client_hash}).")

    def get_total_stored_chars(self) -> int:
        """Calculate total characters stored across all sessions in memory."""
        with self._lock:
            total = 0
            for dq in self._sessions.values():
                for item in dq:
                    total += len(item.get("text", ""))
            return total

    def analyze_escalation(self, current_text, session_id: str = "session_default", client_id: str = None):
        key = self._make_key(session_id, client_id)
        cid = self._resolve_cid(client_id)
        with self._lock:
            if cid in self._client_sessions and session_id in self._client_sessions[cid]:
                self._clients_lru.move_to_end(cid)
                self._client_sessions[cid].move_to_end(session_id)
                if key in self._sessions:
                    self._sessions.move_to_end(key)
                hist_snapshot = list(self._client_sessions[cid][session_id])
            elif key in self._sessions:
                self._sessions.move_to_end(key)
                hist_snapshot = list(self._sessions[key])
            else:
                hist_snapshot = []

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
