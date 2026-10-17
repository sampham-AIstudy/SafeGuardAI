from __future__ import annotations

import functools
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import idna

from codebase.url_analysis.models import Candidate
from codebase.url_analysis.parse import parse_url

MAX_TEXT_CHARS = 20000
MAX_URLS = 20
MAX_CANDIDATES = 200
MAX_URL_LEN = 2048

FILE_EXTENSIONS: set[str] = {
    "docx", "doc", "pdf", "jpg", "jpeg", "png", "gif", "zip", "rar",
    "apk", "exe", "xlsx", "xls", "ppt", "pptx", "mp3", "mp4", "txt",
    "csv", "json", "xml", "iso", "tar", "gz", "7z", "dmg"
}

TRAILING_PUNCT: set[str] = {
    ".", ",", ";", ":", "!", "?", "]", "}", '"', "'", ">", "`", "”", "’", "»"
}
LEADING_PUNCT: set[str] = {
    "(", "[", "{", "<", '"', "'", "`", "“", "‘", "«"
}

# Linear regexes - no '.*', no '.*?', no nested quantifiers
RE_SCHEME = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
RE_DATA_OR_JS = re.compile(r"^(?:data|javascript):", re.IGNORECASE)
RE_MARKDOWN = re.compile(r"\[([^\]\n]{1,500})\]\(([^\)\s\n]{1,2048})\)")


class CandidateList(list):
    """List of Candidate objects with a truncated attribute."""

    def __init__(self, items: list[Candidate] | None = None, truncated: bool = False):
        super().__init__(items or [])
        self.truncated = truncated


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
        "lure_tokens": [],
    }


def get_valid_tlds() -> set[str]:
    return {tld.lower() for tld in load_url_lists().get("valid_tlds", [])}


def get_multi_level_suffixes() -> set[str]:
    return {s.lower() for s in load_url_lists().get("multi_level_suffixes", [])}


def trim_url(raw: str) -> str:
    """
    Trim trailing punctuation (. , ; : ! ? ) ] } ' \" >) and unbalanced ')'.
    Preserve balanced parentheses inside URLs (e.g. Wikipedia links).
    """
    while raw:
        if raw[-1] in TRAILING_PUNCT:
            raw = raw[:-1]
        elif raw.endswith(")"):
            if raw.count("(") < raw.count(")"):
                raw = raw[:-1]
            else:
                break
        else:
            break
    return raw


def _parse_ipv4_part(part: str) -> int | None:
    try:
        if part.lower().startswith("0x"):
            return int(part, 16)
        elif part.startswith("0") and len(part) > 1 and all(c in "01234567" for c in part):
            return int(part, 8)
        elif part.isdigit():
            return int(part, 10)
    except ValueError:
        return None
    return None


def _is_valid_ipv4_host(host: str) -> bool:
    """Validate 1-4 part IPv4 address according to WHATWG rules."""
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return False
    nums: list[int] = []
    for p in parts:
        if not p:
            return False
        val = _parse_ipv4_part(p)
        if val is None or val < 0:
            return False
        nums.append(val)

    if len(nums) == 1:
        return nums[0] <= 0xFFFFFFFF
    elif len(nums) == 2:
        return nums[0] <= 255 and nums[1] <= 0xFFFFFF
    elif len(nums) == 3:
        return nums[0] <= 255 and nums[1] <= 255 and nums[2] <= 0xFFFF
    elif len(nums) == 4:
        return all(n <= 255 for n in nums)
    return False


def _is_standard_dotted_quad_ipv4(host: str) -> bool:
    """
    Check if host is a standard 4-part decimal dotted-quad IPv4 address (a.b.c.d).
    Each part must be 0-255 in decimal with no leading zeros (unless the part is '0').
    Rejects octal, hex, single-int, or shortened IPs.
    """
    if not host:
        return False
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if len(p) > 1 and p.startswith("0"):
            return False
        val = int(p)
        if not (0 <= val <= 255):
            return False
    return True


def _is_bare_ipv4(candidate: str) -> bool:
    """
    Check if candidate without scheme is a valid bare standard dotted-quad IPv4.
    Format: a.b.c.d optionally followed by ':port' (1-65535) and/or '/path' / '?query' / '#fragment'.
    """
    host_port = re.split(r"[/?#]", candidate, maxsplit=1)[0]
    if ":" in host_port:
        parts = host_port.split(":")
        if len(parts) != 2:
            return False
        port_str = parts[1]
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            return False
        host = parts[0]
    else:
        host = host_port

    return _is_standard_dotted_quad_ipv4(host)


def _is_bare_domain(
    candidate: str,
    valid_tlds: set[str],
    multi_suffixes: set[str],
) -> bool:
    """Validate whether candidate qualifies as a bare domain (e.g. vcb-xacminh.com/login, ngânhàng.vn)."""
    # Reject email-like strings without scheme
    if "@" in candidate:
        return False

    # Extract host part before path / query / fragment
    host_part = re.split(r"[/?#]", candidate, maxsplit=1)[0]
    if ":" in host_part:
        parts = host_part.split(":")
        if len(parts) != 2 or not parts[1].isdigit():
            return False
        host_part = parts[0]

    if not host_part or "." not in host_part:
        return False

    # Convert Unicode / IDN domain to punycode ASCII representation
    ascii_host = host_part
    if any(ord(c) > 127 for c in host_part):
        try:
            ascii_host = idna.encode(host_part, uts46=True).decode("ascii")
        except Exception:
            return False

    # Domain characters must be alphanumeric, hyphen, dot
    if not ascii_host or not re.fullmatch(r"[a-zA-Z0-9.-]+", ascii_host):
        return False

    labels = ascii_host.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return False

    # At least one label must contain an ASCII letter
    if not any(any(c.isalpha() for c in label) for label in labels):
        return False

    # Check multi-level suffix (e.g. com.vn)
    if len(labels) >= 2:
        two_part = f"{labels[-2]}.{labels[-1]}".lower()
        if two_part in multi_suffixes:
            # Must have at least one label before the suffix (e.g. vcb.com.vn vs com.vn)
            return len(labels) >= 3

    # Check single-level TLD
    tld = labels[-1].lower()
    if tld in FILE_EXTENSIONS:
        return False
    if tld not in valid_tlds:
        return False

    return True


def _is_userinfo_url(
    candidate: str,
    valid_tlds: set[str],
    multi_suffixes: set[str],
) -> bool:
    """
    Check if candidate is a userinfo decoy URL without scheme, e.g.:
    'vietcombank.com.vn@evil-site.top/xacminh' or 'vcb.com@scam.xyz:8080/portal'.
    Rejects normal emails like 'ten@congty.vn' or 'name@company.com'.
    """
    if "@" not in candidate:
        return False
    parts = candidate.rsplit("@", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return False
    left, right = parts
    left_host = left.split(":", 1)[0]
    right_host_port = re.split(r"[/?#]", right, maxsplit=1)[0]
    has_path_or_port = (len(re.split(r"[/?#]", right, maxsplit=1)) > 1) or (":" in right_host_port)
    if not has_path_or_port:
        return False
    right_host = right_host_port.split(":", 1)[0]
    left_ok = _is_bare_domain(left_host, valid_tlds, multi_suffixes)
    right_ok = _is_bare_domain(right_host, valid_tlds, multi_suffixes) or _is_bare_ipv4(right_host)
    return left_ok and right_ok


class AnchorParser(HTMLParser):
    """HTML parser to extract <a href="...">display_text</a> candidates."""

    def __init__(self, text: str):
        super().__init__()
        self.text = text
        self.line_starts = [0]
        for i, c in enumerate(text):
            if c == "\n":
                self.line_starts.append(i + 1)
        self.anchors: list[dict[str, Any]] = []
        self._curr_start = 0
        self._curr_href: str | None = None
        self._curr_text: list[str] = []

    def _get_pos_index(self) -> int:
        line, col = self.getpos()
        if 1 <= line <= len(self.line_starts):
            return self.line_starts[line - 1] + col
        return len(self.text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._curr_start = self._get_pos_index()
            self._curr_href = None
            self._curr_text = []
            for k, v in attrs:
                if k.lower() == "href" and v:
                    self._curr_href = v

    def handle_data(self, data: str) -> None:
        if self._curr_href is not None:
            self._curr_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._curr_href is not None:
            end_pos = self._get_pos_index()
            closing_tag = f"</{tag}>"
            if self.text[end_pos : end_pos + len(closing_tag)].lower() == closing_tag.lower():
                end_pos += len(closing_tag)
            display = "".join(self._curr_text).strip()
            self.anchors.append(
                {
                    "href": self._curr_href.strip(),
                    "display_text": display if display else None,
                    "start": self._curr_start,
                    "end": max(end_pos, self._curr_start + 1),
                }
            )
            self._curr_href = None


def extract_candidates(
    clean_text: str,
    extra_urls: list[Any] | None = None,
    stats: dict[str, Any] | None = None,
) -> CandidateList:
    """
    Extract candidate URLs from cleaned text and extra URL sources.

    Recognized:
      1. Schemed URLs (http, https, ftp, data:, javascript:).
      2. www. prefixed domains.
      3. Bare domains (label + valid TLD, at least one label containing a letter).
      4. IPv4 addresses (decimal/hex/octal/shortened) with scheme or followed by '/' or ':port'.
      5. HTML anchors <a href="...">text</a> (using HTMLParser).
      6. Markdown links [text](url).

    Rejected:
      - Emails (x@y.vn without scheme) and domains inside email.
      - Amounts (500.000đ), versions (v2.0, 1.2.3), decimals (3.14).
      - Standalone files (baocao.docx, img.jpg).
      - Short non-TLD 'a.b', standalone 'www', phone numbers, dates, standalone 'com.vn'.

    Returns:
      CandidateList of Candidate objects (deduplicated, order preserved, capped at MAX_URLS=20).
    """
    valid_tlds = get_valid_tlds()
    multi_suffixes = get_multi_level_suffixes()

    if len(clean_text) > MAX_TEXT_CHARS:
        clean_text = clean_text[:MAX_TEXT_CHARS]

    candidates: list[Candidate] = []
    consumed_spans: list[tuple[int, int]] = []

    def _is_consumed(s: int, e: int) -> bool:
        for cs, ce in consumed_spans:
            if max(s, cs) < min(e, ce):
                return True
        return False

    # 1. Markdown links: [text](url)
    for m in RE_MARKDOWN.finditer(clean_text):
        m_start = m.start()
        m_end = m.end()
        display_text = m.group(1).strip()
        raw_url = trim_url(m.group(2).strip())
        if raw_url:
            candidates.append(
                Candidate(
                    raw=raw_url,
                    start=m_start,
                    end=m_end,
                    source="markdown",
                    display_text=display_text if display_text else None,
                    is_long=len(raw_url) > MAX_URL_LEN,
                )
            )
            consumed_spans.append((m_start, m_end))

    # 2. HTML anchor tags: <a href="...">text</a>
    if "<a" in clean_text.lower():
        parser = AnchorParser(clean_text)
        try:
            parser.feed(clean_text)
        except Exception:
            pass
        for item in parser.anchors:
            href = trim_url(item["href"])
            a_start = item["start"]
            a_end = item["end"]
            if href and not _is_consumed(a_start, a_end):
                candidates.append(
                    Candidate(
                        raw=href,
                        start=a_start,
                        end=a_end,
                        source="anchor",
                        display_text=item["display_text"],
                        is_long=len(href) > MAX_URL_LEN,
                    )
                )
                consumed_spans.append((a_start, a_end))

    # 3. Plain text tokens
    for m in re.finditer(r"\S+", clean_text):
        tok_start = m.start()
        tok_end = m.end()
        if _is_consumed(tok_start, tok_end):
            continue

        token_str = m.group(0)

        # Strip leading punctuation
        stripped_left = token_str.lstrip("".join(LEADING_PUNCT))
        lead_len = len(token_str) - len(stripped_left)
        if not stripped_left:
            continue

        # Trim trailing punctuation and unbalanced parentheses
        candidate_str = trim_url(stripped_left)
        if not candidate_str:
            continue

        c_start = tok_start + lead_len
        c_end = c_start + len(candidate_str)

        # Check URL validity
        is_url = False

        # Form A: Scheme URLs (http, https, ftp, data:, javascript:) including loose schemes
        if RE_SCHEME.match(candidate_str):
            is_url = True
        elif candidate_str.lower().startswith(("http:/", "https:/", "ftp:/", "http:\\", "https:\\", "ftp:\\", "http:", "https:", "ftp:")):
            p = parse_url(candidate_str)
            if p.effective_host:
                is_url = True
        elif candidate_str.startswith("//"):
            host_cand = re.split(r"[/?#:]", candidate_str[2:], maxsplit=1)[0]
            if _is_bare_domain(host_cand, valid_tlds, multi_suffixes) or _is_bare_ipv4(host_cand):
                is_url = True
        # Form B: data: or javascript: URI
        elif RE_DATA_OR_JS.match(candidate_str):
            is_url = True
        # Form C: www. prefix
        elif candidate_str.lower().startswith("www."):
            host_part = re.split(r"[/?#]", candidate_str, maxsplit=1)[0].split(":")[0]
            labels = host_part.split(".")
            # www alone or www. alone is not a valid URL
            if len(labels) >= 3 and _is_bare_domain(host_part, valid_tlds, multi_suffixes):
                is_url = True
        # Form D: Standard dotted-quad IPv4 without scheme (e.g. 192.168.1.1, 103.2.3.4:8080/x, 103.2.3.4/login)
        elif _is_bare_ipv4(candidate_str):
            is_url = True
        # Form E: Userinfo URL without scheme (e.g. vietcombank.com.vn@evil.xyz/login)
        elif _is_userinfo_url(candidate_str, valid_tlds, multi_suffixes):
            is_url = True
        # Form F: Bare domain (e.g. vcb-xacminh.com/login, google.com, ngânhàng.vn)
        elif _is_bare_domain(candidate_str, valid_tlds, multi_suffixes):
            is_url = True

        if is_url:
            candidates.append(
                Candidate(
                    raw=candidate_str,
                    start=c_start,
                    end=c_end,
                    source="text",
                    display_text=None,
                    is_long=len(candidate_str) > MAX_URL_LEN,
                )
            )

    # 4. Extra URLs (e.g. from QR code or OCR)
    if extra_urls:
        for item in extra_urls:
            if isinstance(item, Candidate):
                candidates.append(item)
            elif isinstance(item, (tuple, list)):
                u = str(item[0]) if len(item) > 0 else ""
                s = str(item[1]) if len(item) > 1 else "extra"
                d = str(item[2]) if len(item) > 2 else None
                if u:
                    candidates.append(
                        Candidate(
                            raw=u,
                            start=-1,
                            end=-1,
                            source=s,
                            display_text=d,
                            is_long=len(u) > MAX_URL_LEN,
                        )
                    )
            elif isinstance(item, dict):
                u = str(item.get("raw") or item.get("url") or "")
                s = str(item.get("source") or "extra")
                d = item.get("display_text")
                if u:
                    candidates.append(
                        Candidate(
                            raw=u,
                            start=-1,
                            end=-1,
                            source=s,
                            display_text=d,
                            is_long=len(u) > MAX_URL_LEN,
                        )
                    )
            elif isinstance(item, str) and item:
                candidates.append(
                    Candidate(
                        raw=item,
                        start=-1,
                        end=-1,
                        source="extra",
                        display_text=None,
                        is_long=len(item) > MAX_URL_LEN,
                    )
                )

    # 5. Deduplicate while preserving order
    seen_urls: set[str] = set()
    unique_candidates: list[Candidate] = []
    for c in candidates:
        if c.raw in seen_urls:
            continue
        seen_urls.add(c.raw)
        unique_candidates.append(c)

    # 6. Apply MAX_CANDIDATES limit
    truncated = len(unique_candidates) > MAX_CANDIDATES
    if truncated:
        unique_candidates = unique_candidates[:MAX_CANDIDATES]

    if stats is not None:
        stats["truncated"] = truncated
        stats["truncated_urls"] = truncated

    return CandidateList(unique_candidates, truncated=truncated)
