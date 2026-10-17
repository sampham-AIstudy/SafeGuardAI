import re
import math
from typing import Any

# Bounded linear regex for cleaning
# Control chars: 0x00-0x08, 0x0b, 0x0c, 0x0e-0x1f, 0x7f
# Bidi: \u061c, \u200e, \u200f, \u202a-\u202e, \u2066-\u2069
# Zero-width: \u200b-\u200d, \u2060, \ufeff
BIDI_CONTROL_ZEROWIDTH_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u200b-\u200d\u2060\ufeff]"
)
HTML_TAG_RE = re.compile(r"<[^>\n]{0,200}>")

ALLOWED_INTENTS = {"general_chat", "need_more_info", "scam_analysis", "refusal"}


def clean_llm_string(val: Any, max_len: int = 300) -> str:
    """
    Sanitize a string from LLM:
    - Removes HTML tags via linear bounded regex
    - Escapes any remaining angle brackets
    - Strips NUL, control, bidi, and zero-width characters
    - Clamps to max_len
    """
    if val is None:
        return ""
    if not isinstance(val, str):
        val = str(val)
    # Remove HTML tags using bounded regex
    s = HTML_TAG_RE.sub("", val)
    # Escape any remaining angle brackets
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    # Remove control, bidi, and zero-width characters
    s = BIDI_CONTROL_ZEROWIDTH_RE.sub("", s)
    s = s.strip()
    return s[:max_len]


def sanitize_llm_output(raw: Any) -> dict | None:
    """
    Validate and sanitize LLM output dictionary for both single and agentic pipelines.
    Enforces:
    - risk_score: finite numeric coerced to int and clamped to 0..99 (non-finite/non-numeric returns None)
    - intent_type: strictly within ALLOWED_INTENTS
    - strings: bidi/control/zero-width stripped, HTML tags stripped/escaped, length limits (reply <= 600, items <= 300)
    - lists: max 10 string items
    - unknown fields: completely dropped
    """
    if not isinstance(raw, dict):
        return None

    # 1. Validate risk_score
    if "risk_score" not in raw or raw["risk_score"] is None:
        raw_intent = raw.get("intent_type") or raw.get("intent")
        if raw_intent in ("general_chat", "need_more_info"):
            risk_int = 0
        else:
            return None
    else:
        raw_risk = raw["risk_score"]
        if isinstance(raw_risk, bool):
            return None
        try:
            f_risk = float(raw_risk)
            if not math.isfinite(f_risk):
                return None
            risk_int = int(f_risk)
        except (ValueError, TypeError, OverflowError, ArithmeticError):
            return None

    risk_score = max(0, min(99, risk_int))

    # 2. Validate intent_type
    raw_intent = raw.get("intent_type") or raw.get("intent")
    if raw_intent and isinstance(raw_intent, str) and raw_intent.strip() in ALLOWED_INTENTS:
        intent_type = raw_intent.strip()
    else:
        intent_type = "scam_analysis"

    # 3. Clean conversational_reply / headline (<= 600 chars)
    raw_reply = raw.get("conversational_reply")
    if raw_reply is None and "headline" in raw:
        raw_reply = raw["headline"]
    conversational_reply = clean_llm_string(raw_reply, max_len=600)

    # 4. Clean list fields (max 10 items, <= 300 chars each)
    def _clean_str_list(items: Any) -> list[str]:
        if not isinstance(items, list):
            return []
        res = []
        for it in items:
            if not isinstance(it, str):
                continue
            cleaned = clean_llm_string(it, max_len=300)
            if cleaned:
                res.append(cleaned)
            if len(res) >= 10:
                break
        return res

    explanation_breakdown = _clean_str_list(raw.get("explanation_breakdown") or raw.get("reasons"))
    recommendations = _clean_str_list(raw.get("recommendations"))

    return {
        "intent_type": intent_type,
        "conversational_reply": conversational_reply,
        "risk_score": risk_score,
        "explanation_breakdown": explanation_breakdown,
        "recommendations": recommendations,
    }
