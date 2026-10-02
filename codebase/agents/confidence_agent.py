class ConfidenceAgent:
    """
    Confidence Agent:
    Evaluates AI Model Confidence Score based on matched Red Flags count
    and Knowledge Base pattern match ratio.
    Triggers Human Verification fallback when Confidence is LOW.
    """
    def __init__(self):
        pass

    def evaluate(self, matched_flags_count, total_patterns_matched, risk_score):
        confidence_score = 50
        reason = ""
        level = "MEDIUM"

        if matched_flags_count >= 3 or total_patterns_matched >= 2:
            confidence_score = 98
            level = "HIGH"
            reason = f"Độ tin cậy cao: Trùng khớp {matched_flags_count} dấu hiệu đỏ và {total_patterns_matched} mẫu kịch bản CSDL lừa đảo."
        elif matched_flags_count == 1 or matched_flags_count == 2:
            confidence_score = 75
            level = "MEDIUM"
            reason = f"Độ tin cậy vừa: Khớp {matched_flags_count} dấu hiệu nghi vấn."
        else:
            confidence_score = 40
            level = "LOW"
            reason = "Độ tin cậy thấp: Không tìm thấy đủ dấu hiệu đối soát rõ ràng."

        recommend_human_verification = (level == "LOW" or (risk_score >= 40 and risk_score <= 60))

        return {
            "confidence_score": confidence_score,
            "confidence_level": level,
            "reason": reason,
            "recommend_human_verification": recommend_human_verification
        }

if __name__ == "__main__":
    conf = ConfidenceAgent()
    res = conf.evaluate(matched_flags_count=4, total_patterns_matched=3, risk_score=96)
    print("[ConfidenceAgent] Result:", res)
