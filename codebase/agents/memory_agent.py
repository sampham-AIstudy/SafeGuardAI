class MemoryAgent:
    """
    Memory Agent:
    Maintains interaction history across multi-turn / multi-day conversations
    to detect escalating sequential scam patterns (e.g. Day 1 -> Day 3 -> Day 5).
    Integrates directly with MySQL Database to persist and reload context.
    """
    def __init__(self):
        self.history = []

    def add_interaction(self, user_text, risk_level, matched_flags):
        self.history.append({
            "text": user_text,
            "risk_level": risk_level,
            "flags": matched_flags
        })

    def load_history_from_db(self, db_manager, session_id):
        """Loads interaction history from MySQL database for a specific session."""
        if not db_manager or not db_manager.is_connected:
            return
        db_history = db_manager.get_chat_history(session_id)
        if db_history:
            self.history = []
            for row in db_history:
                flags = []
                user_text = row.get("user_text", "")
                risk_level = row.get("risk_level", "LOW")
                self.history.append({
                    "text": user_text,
                    "risk_level": risk_level,
                    "flags": flags
                })
            print(f"[MemoryAgent] Successfully loaded {len(self.history)} historical records from MySQL for session `{session_id}`.")

    def analyze_escalation(self, current_text):
        escalation_detected = False
        escalation_reason = ""
        all_flags = []

        for item in self.history:
            all_flags.extend(item.get("flags", []))

        # Example escalation: Job post -> Transfer money / deposit
        has_recruitment = any("tuyển" in item["text"].lower() or "việc" in item["text"].lower() for item in self.history)
        current_has_transfer = any(w in current_text.lower() for w in ["chuyển tiền", "nạp", "500k", "quỹ", "cọc", "bill"])

        if has_recruitment and current_has_transfer:
            escalation_detected = True
            escalation_reason = "Phát hiện chuỗi lừa đảo leo thang (Sequential Scam Pattern): Từ tuyển dụng việc làm $\\rightarrow$ Yêu cầu nạp tiền/chuyển khoản."

        return {
            "history_count": len(self.history),
            "escalation_detected": escalation_detected,
            "escalation_reason": escalation_reason,
            "accumulated_flags": list(set(all_flags))
        }

if __name__ == "__main__":
    mem = MemoryAgent()
    mem.add_interaction("Anh ơi em tìm được việc làm tuyển dụng xem TikTok 500k/ngày", "LOW", ["tuyển dụng"])
    res = mem.analyze_escalation("Họ bảo em phải chuyển 500k cọc quỹ đảm bảo mới cho nhận việc")
    print("[MemoryAgent] Escalation Result:", res)
