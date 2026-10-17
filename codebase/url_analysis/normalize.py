from __future__ import annotations

import functools
import html
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from codebase.url_analysis.models import ObfuscationStep

MAX_TEXT_CHARS = 20000

# Zero-width and invisible characters per UPGRADE_PLAN section 3.2
# U+00AD, U+034F, U+061C, U+115F/1160, U+17B4/5, U+180B-180E, U+200B-200F,
# U+202A-202E, U+2060-2064, U+2066-206F, U+3164, U+FEFF, U+FFA0
ZERO_WIDTH_CHARS: set[str] = set(
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5"
    "\u180b\u180c\u180d\u180e"
    "\u200b\u200c\u200d\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064"
    "\u2066\u2067\u2068\u2069\u206a\u206b\u206c\u206d\u206e\u206f"
    "\u3164\ufeff\uffa0"
)

# Odd dots to normalize to ASCII '.'
ODD_DOTS: set[str] = {"\u3002", "\uff0e", "\uff61"}

# Linear regex patterns without nested quantifiers or '.*'
RE_SCHEME_DEFANG = re.compile(r"\b(hxx[pP][sS]?|h\*\*[pP][sS]?)\b", re.IGNORECASE)
RE_COLON_SLASHES = re.compile(r"\[:\]//|\[://\]", re.IGNORECASE)
RE_SCHEME_COLON = re.compile(r"\b(https?|ftp)\[:\](//)?", re.IGNORECASE)
RE_BRACKET_DOT = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.IGNORECASE)

# Linear bounded regex for ' dot ', ' . ', ' cham ', ' chấm ', commas and strange Unicode dots (‥ ․ ﹒ ・)
RE_SPACED_DOT = re.compile(
    r"([a-zA-Z0-9\-\u00c0-\u024f\u1ea0-\u1ef9])"
    r"(?:"
    r"[ \t]*(?:,|\u2024|\u2025|\ufe52|\u30fb)[ \t]*|"
    r"[ \t]+(?:\.|\bdot\b|\bch[aấá]m\b|\bcham\b)[ \t]+"
    r")"
    r"([a-zA-Z]{2,63})"
    r"(?=[/?#\s,;:]|$)",
    re.IGNORECASE,
)

RE_TAB_URL = re.compile(r"((?:https?|ftp)://[^\s\r\n]{1,500})\t([^\s\r\n]{1,500})", re.IGNORECASE)
RE_NL_URL = re.compile(r"((?:https?|ftp)://[^\s\r\n]{1,500})\r?\n([a-zA-Z0-9/_?&=-]{1,500})", re.IGNORECASE)


class NormalizeStats(dict):
    """Normalization statistics supporting both dict and attribute access."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'NormalizeStats' has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


@functools.lru_cache(maxsize=1)
def load_url_lists() -> dict[str, Any]:
    """Load URL configuration lists from knowledge_base/url_lists.json."""
    kb_path = Path(__file__).resolve().parent.parent / "knowledge_base" / "url_lists.json"
    if kb_path.exists():
        with open(kb_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "shorteners": [],
        "redirectors": {},
        "free_hosting": [],
        "suspicious_tlds": [],
        "multi_level_suffixes": [],
        "valid_tlds": [],
    }


def get_valid_tlds() -> set[str]:
    """Return set of lowercase valid TLDs."""
    lists = load_url_lists()
    return {tld.lower() for tld in lists.get("valid_tlds", [])}


def _refang_scheme_match(m: re.Match) -> str:
    raw = m.group(0)
    has_s = raw.lower().endswith("s")
    base = "https" if has_s else "http"
    if raw.isupper():
        return base.upper()
    elif raw[0].isupper():
        return base.capitalize()
    return base


def normalize_for_urls(
    text: str,
    valid_tlds: set[str] | None = None,
) -> tuple[str, list[ObfuscationStep], NormalizeStats]:
    """
    Normalize text to detect and refang obfuscated URLs.

    Pipeline:
      0. Truncate at MAX_TEXT_CHARS=20000.
      1. Strip zero-width/invisible characters (count and record).
      2. Decode HTML entities (html.unescape).
      3. Unicode NFKC (fullwidth to ASCII, preserving Vietnamese precomposed NFC).
      4. Convert odd dots (。．｡) to standard dot (.).
      5. Refang scheme and dots (hxxp, h**p, [:], [.]/(.)/{.}, ' dot ', ' . ').
         Note: ' dot ' and ' . ' are only refanged when the right-hand side is a known TLD.

    Returns:
      (clean_text, steps, stats)
    """
    if valid_tlds is None:
        valid_tlds = get_valid_tlds()

    original_length = len(text)
    truncated = original_length > MAX_TEXT_CHARS
    if truncated:
        text = text[:MAX_TEXT_CHARS]

    stats = NormalizeStats(
        truncated=truncated,
        removed_zero_width_chars=0,
        original_length=original_length,
        cleaned_length=len(text),
    )
    steps: list[ObfuscationStep] = []

    # Step 1: Remove zero-width / invisible characters
    zero_width_count = sum(1 for c in text if c in ZERO_WIDTH_CHARS)
    if zero_width_count > 0:
        clean_no_zw = "".join(c for c in text if c not in ZERO_WIDTH_CHARS)
        steps.append(
            ObfuscationStep(
                technique="zero_width",
                detail_vi=f"Đã phát hiện và gỡ bỏ {zero_width_count} ký tự ẩn/zero-width",
                before=text[:200],
                after=clean_no_zw[:200],
            )
        )
        text = clean_no_zw
        stats.removed_zero_width_chars = zero_width_count

    # Step 2: HTML entities
    unescaped = html.unescape(text)
    if unescaped != text:
        steps.append(
            ObfuscationStep(
                technique="html_entity",
                detail_vi="Giải mã thực thể HTML (HTML entity) trong văn bản",
                before=text[:200],
                after=unescaped[:200],
            )
        )
        text = unescaped

    # Step 3: Unicode NFKC (fullwidth -> ASCII)
    nfkc_text = unicodedata.normalize("NFKC", text)
    if nfkc_text != text:
        steps.append(
            ObfuscationStep(
                technique="fullwidth",
                detail_vi="Chuẩn hóa ký tự Unicode toàn phần (fullwidth/NFKC) về dạng tiêu chuẩn",
                before=text[:200],
                after=nfkc_text[:200],
            )
        )
        text = nfkc_text

    # Step 4: Odd dots (。．｡)
    if any(c in ODD_DOTS for c in text):
        odd_fixed = "".join("." if c in ODD_DOTS else c for c in text)
        steps.append(
            ObfuscationStep(
                technique="defanged",
                detail_vi="Chuyển đổi ký tự dấu chấm lạ (。/．/｡) về dấu chấm tiêu chuẩn",
                before=text[:200],
                after=odd_fixed[:200],
            )
        )
        text = odd_fixed

    # Step 5: Refang schemes and separators
    # 5a: hxxp / h**p
    if "hxx" in text.lower() or "h**" in text.lower():
        scheme_fixed = RE_SCHEME_DEFANG.sub(_refang_scheme_match, text)
        if scheme_fixed != text:
            steps.append(
                ObfuscationStep(
                    technique="defanged",
                    detail_vi="Khôi phục scheme URL bị làm mờ (hxxp/h**p -> http(s))",
                    before=text[:200],
                    after=scheme_fixed[:200],
                )
            )
            text = scheme_fixed

    # 5b: [:]// or [://] -> ://, and scheme[:]// -> scheme://
    if "[:]" in text or "[://]" in text:
        colon_fixed = RE_COLON_SLASHES.sub("://", text)
        colon_fixed = RE_SCHEME_COLON.sub(
            lambda m: f"{m.group(1)}://" if m.group(2) else f"{m.group(1)}:",
            colon_fixed,
        )
        if colon_fixed != text:
            steps.append(
                ObfuscationStep(
                    technique="defanged",
                    detail_vi="Khôi phục dấu phân cách scheme bị làm mờ ([:]// hoặc [://] -> ://)",
                    before=text[:200],
                    after=colon_fixed[:200],
                )
            )
            text = colon_fixed

    # 5c: Bracket dots [.] (.) {.} [dot] (dot) {dot}
    if any(c in text for c in "([{"):
        bracket_fixed = RE_BRACKET_DOT.sub(".", text)
        if bracket_fixed != text:
            steps.append(
                ObfuscationStep(
                    technique="defanged",
                    detail_vi="Khôi phục dấu chấm phân tách domain bị làm mờ ([.]/(.)/[dot]/(dot) -> .)",
                    before=text[:200],
                    after=bracket_fixed[:200],
                )
            )
            text = bracket_fixed

    # 5d: Spaced dots: ' dot ', ' . ', ' cham ', ' chấm ', commas, and strange Unicode dots (‥ ․ ﹒ ・)
    has_spaced_dot_trigger = (
        " dot " in text.lower()
        or " . " in text
        or "cham" in text.lower()
        or any(k in text for k in ("chấm", "chám", "châm", "\u2024", "\u2025", "\ufe52", "\u30fb"))
        or ("," in text and any(c.isalpha() for c in text))
    )
    if has_spaced_dot_trigger:
        def _replace_spaced_dot(m: re.Match) -> str:
            left = m.group(1)
            right = m.group(2)
            if right.lower() in valid_tlds:
                return f"{left}.{right}"
            return m.group(0)

        cur_text = text
        for _ in range(5):  # loop up to 5 passes for chained spaced dots like vcb . com . vn
            next_text = RE_SPACED_DOT.sub(_replace_spaced_dot, cur_text)
            if next_text == cur_text:
                break
            cur_text = next_text

        if cur_text != text:
            steps.append(
                ObfuscationStep(
                    technique="defanged",
                    detail_vi="Khôi phục dấu phân cách domain bị làm mờ (' dot ', ' chấm ', dấu phẩy hoặc ký tự chấm lạ -> .)",
                    before=text[:200],
                    after=cur_text[:200],
                )
            )
            text = cur_text

    # 5e: Tab or newline inside a schemed URL (WHATWG URL parsing ignores tabs/newlines within URLs)
    if "\t" in text and "://" in text:
        cur_text = text
        for _ in range(10):
            next_text = RE_TAB_URL.sub(r"\1\2", cur_text)
            if next_text == cur_text:
                break
            cur_text = next_text
        if cur_text != text:
            steps.append(
                ObfuscationStep(
                    technique="defanged",
                    detail_vi="Khôi phục liên kết bị chèn ký tự tab (\\t) làm gián đoạn",
                    before=text[:200],
                    after=cur_text[:200],
                )
            )
            text = cur_text

    if "\n" in text and "://" in text:
        cur_text = text
        for _ in range(5):
            next_text = RE_NL_URL.sub(r"\1\2", cur_text)
            if next_text == cur_text:
                break
            cur_text = next_text
        if cur_text != text:
            steps.append(
                ObfuscationStep(
                    technique="defanged",
                    detail_vi="Ghép liên kết bị ngắt dòng bất thường",
                    before=text[:200],
                    after=cur_text[:200],
                )
            )
            text = cur_text

    stats.cleaned_length = len(text)
    return text, steps, stats
