"""
codebase/text_utils.py
Text utilities for Vietnamese text normalization, invisible character stripping,
text variant generation, and robust phrase matching.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Set, Tuple, Union

# Regex for invisible / zero-width / bidi / formatting characters
# U+00AD, U+034F, U+061C, U+115F, U+1160, U+17B4, U+17B5, U+180B-U+180E,
# U+200B-U+200F, U+202A-U+202E, U+2060-U+2064, U+2066-U+206F, U+3164, U+FEFF, U+FFA0
INVISIBLE_PATTERN = re.compile(
    r"[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E"
    r"\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F"
    r"\u3164\uFEFF\uFFA0]"
)

# Negation pattern for credentials, verbs, and scam actions:
# không|đừng|chớ|tuyệt đối không|không bao giờ|không được|không nên|chưa|khong|dung
NEGATION_TERMS = (
    r"(?:tuyệt\s+đối\s+không|không\s+bao\s+giờ|không\s+được|không\s+nên|"
    r"tuyet\s+doi\s+khong|khong\s+bao\s+gio|khong\s+duoc|khong\s+nen|"
    r"không|khong|đừng|dung|chớ|chưa|chua)"
)

OPTIONAL_ACTIONS = (
    r"(?:\s+(?:ai\s+)?(?:được|duoc|bao\s+giờ|bao\s+gio|phép|phep))?"
    r"(?:\s+(?:chia\s+sẻ|chia\s+se|cung\s+cấp|cung\s+cap|tiết\s+lộ|tiet\s+lo|cho|gửi|gui|nhập|nhap|bấm|bam|đưa|dua|lộ|lo))?"
    r"(?:\s+(?:bất\s+kỳ|bat\s+ky|mọi|moi|bất\s+cứ|bat\s+cu))?"
    r"(?:\s+(?:thông\s+tin|thong\s+tin|mã|ma|số|so|mật\s+mã|mat\s+ma))?"
)

CONJUNCTION = (
    r"(?:\s*(?:otp|mã\s+otp|ma\s+otp|stk|cccd|cmnd|tài\s+khoản|tai\s+khoan|thẻ|the)?\s*(?:và|va|hoặc|hoac|,|\/|\+)\s*)?"
    r"(?:\s*(?:thông\s+tin|thong\s+tin|mã|ma|số|so|mật\s+mã|mat\s+ma))?"
)

NEGATION_PATTERN = re.compile(
    rf"{NEGATION_TERMS}{OPTIONAL_ACTIONS}{CONJUNCTION}\s*$",
    re.IGNORECASE,
)

CREDENTIAL_KEYWORDS = {"otp", "mat khau", "mật khẩu", "password", "ma xac", "cvv", "stk"}


def strip_invisible(text: str) -> Tuple[str, int]:
    """
    Remove invisible and zero-width characters from text.
    Returns (cleaned_text, removed_count).
    """
    if not text:
        return "", 0
    matches = INVISIBLE_PATTERN.findall(text)
    count = len(matches)
    if count == 0:
        return text, 0
    cleaned = INVISIBLE_PATTERN.sub("", text)
    return cleaned, count


def fold_vietnamese(text: str) -> str:
    """
    Fold Vietnamese accented text to unaccented ASCII-like characters.
    Performs NFD decomposition, strips Mn combining marks, replaces đ/Đ with d/D,
    and returns NFC normalized string.
    """
    if not text:
        return ""
    # Replace đ / Đ before decomposing
    text_d = text.replace("đ", "d").replace("Đ", "D")
    nfd = unicodedata.normalize("NFD", text_d)
    stripped = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    return unicodedata.normalize("NFC", stripped)


@dataclass
class TextVariants:
    original: str
    clean: str
    lower: str
    folded: str
    invisible_count: int


def make_variants(text: str, max_chars: int = 20000) -> TextVariants:
    """
    Generate TextVariants for a given input text, truncating to max_chars if longer.
    Normalizes unicodedata NFKC then NFC before lowercasing/unaccenting.
    """
    if text is None:
        text = ""
    # Normalize NFKC then NFC before stripping / processing
    text = unicodedata.normalize("NFKC", text)
    text = unicodedata.normalize("NFC", text)
    if len(text) > max_chars:
        text = text[:max_chars]

    clean, inv_count = strip_invisible(text)
    clean = unicodedata.normalize("NFKC", clean)
    clean = unicodedata.normalize("NFC", clean)
    lower = clean.lower()
    folded = fold_vietnamese(lower)

    return TextVariants(
        original=text,
        clean=clean,
        lower=lower,
        folded=folded,
        invisible_count=inv_count,
    )


class PhraseMatcher:
    """
    Regex-based phrase matcher with literal alternation, word boundary checks,
    optional unaccented (folded) matching, and credential negation handling.
    """

    def __init__(
        self,
        phrases: Iterable[str],
        allow_folded: bool = True,
        min_folded_tokens: int = 2,
        folded_allowlist: Sequence[str] = ("otp", "apk", "stk", "cvv"),
        check_negation: bool = True,
        negation_window: int = 30,
    ):
        self.allow_folded = allow_folded
        self.min_folded_tokens = min_folded_tokens
        self.folded_allowlist = set(f.lower() for f in folded_allowlist)
        self.check_negation = check_negation
        self.negation_window = negation_window

        # Store canonical phrases and compile regex patterns
        # Map: normalized_lower_pattern -> canonical_phrase
        self._accented_phrases: List[Tuple[str, str]] = []
        self._folded_phrases: List[Tuple[str, str]] = []

        seen_accented: Set[str] = set()
        seen_folded: Set[str] = set()

        for raw_phrase in phrases:
            p = (raw_phrase or "").strip()
            if not p:
                continue

            p_lower = p.lower()
            if p_lower not in seen_accented:
                seen_accented.add(p_lower)
                self._accented_phrases.append((p_lower, p))

            if self.allow_folded:
                p_folded = fold_vietnamese(p_lower).strip()
                tokens = p_folded.split()
                # Condition: phrase must have >= min_folded_tokens OR be in allowlist
                is_allowed = len(tokens) >= self.min_folded_tokens or (
                    len(tokens) == 1 and tokens[0] in self.folded_allowlist
                )
                if is_allowed and p_folded not in seen_folded:
                    seen_folded.add(p_folded)
                    self._folded_phrases.append((p_folded, p))

        # Sort by length descending for greedy matching
        self._accented_phrases.sort(key=lambda item: len(item[0]), reverse=True)
        self._folded_phrases.sort(key=lambda item: len(item[0]), reverse=True)

        self._accented_regex = self._compile_alternation([p[0] for p in self._accented_phrases])
        self._folded_regex = (
            self._compile_alternation([p[0] for p in self._folded_phrases])
            if self._folded_phrases
            else None
        )

        # Mapping dictionaries for quick phrase resolution
        self._accented_map = {item[0]: item[1] for item in self._accented_phrases}
        self._folded_map = {item[0]: item[1] for item in self._folded_phrases}

    @staticmethod
    def _compile_alternation(phrases: List[str]) -> re.Pattern | None:
        if not phrases:
            return None

        parts = []
        for phrase in phrases:
            # Handle inner whitespace flexibly (\s+) while escaping other characters
            tokens = [re.escape(t) for t in phrase.split()]
            parts.append(r"\s+".join(tokens))

        combined = "|".join(parts)
        # One lookbehind, one lookahead outside the alternation group for linear speed
        return re.compile(rf"(?<!\w)(?:{combined})(?!\w)", re.IGNORECASE)

    def _is_negated(self, text: str, start_idx: int, phrase: str) -> bool:
        if not self.check_negation:
            return False

        window_start = max(0, start_idx - self.negation_window)
        window_text = text[window_start:start_idx]
        return bool(NEGATION_PATTERN.search(window_text))

    def _get_variants(self, text_or_variants: Union[str, TextVariants]) -> TextVariants:
        if isinstance(text_or_variants, TextVariants):
            return text_or_variants
        return make_variants(text_or_variants)

    def search(self, text_or_variants: Union[str, TextVariants]) -> bool:
        """Return True if at least one unnegated phrase matches."""
        return len(self.findall(text_or_variants)) > 0

    def findall(self, text_or_variants: Union[str, TextVariants]) -> List[str]:
        """
        Find all unique canonical phrases matching the text.
        Applies negation window check to credential terms.
        """
        variants = self._get_variants(text_or_variants)
        matched_canonical: List[str] = []
        seen: Set[str] = set()

        # 1. Match against clean lower (accented)
        if self._accented_regex:
            for m in self._accented_regex.finditer(variants.lower):
                matched_str = m.group(0).lower()
                norm_key = " ".join(matched_str.split())
                canonical = self._accented_map.get(norm_key, m.group(0))

                if self._is_negated(variants.clean, m.start(), canonical):
                    continue

                if canonical not in seen:
                    seen.add(canonical)
                    matched_canonical.append(canonical)

        # 2. Match against folded (unaccented)
        if self._folded_regex:
            for m in self._folded_regex.finditer(variants.folded):
                matched_str = m.group(0).lower()
                norm_key = " ".join(matched_str.split())
                canonical = self._folded_map.get(norm_key, m.group(0))

                if self._is_negated(variants.clean, m.start(), canonical) or self._is_negated(variants.folded, m.start(), canonical):
                    continue

                if canonical not in seen:
                    seen.add(canonical)
                    matched_canonical.append(canonical)

        return matched_canonical

    def find_all(self, text_or_variants: Union[str, TextVariants]) -> List[str]:
        """Alias for findall."""
        return self.findall(text_or_variants)

    def __contains__(self, text_or_variants: Union[str, TextVariants]) -> bool:
        return self.search(text_or_variants)
