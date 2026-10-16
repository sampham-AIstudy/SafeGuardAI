from __future__ import annotations

import base64
import functools
import re
import urllib.parse
from typing import Any

from codebase.url_analysis.models import Candidate, ObfuscationStep, ParsedUrl, PeelResult
from codebase.url_analysis.normalize import get_valid_tlds, load_url_lists
from codebase.url_analysis.parse import parse_url

MAX_DEPTH = 4
MAX_INNER_URLS = 10
MAX_DECODED_CHARS = 4096

COMMON_REDIRECT_PARAMS: set[str] = {
    "url", "u", "q", "link", "target", "dest", "destination",
    "redirect", "redirect_uri", "next", "continue", "goto", "r",
    "out", "to", "return", "returnurl", "rurl", "data"
}

RE_BASE64_TOKEN = re.compile(r"^[A-Za-z0-9_\-+/=]{16,4096}$")
RE_HEX_TOKEN = re.compile(r"^[0-9a-fA-F]{20,4096}$")


@functools.lru_cache(maxsize=1)
def get_redirectors_config() -> dict[str, list[str]]:
    """Return dictionary of trusted redirector patterns and their parameter names."""
    lists = load_url_lists()
    return lists.get("redirectors", {})


def _is_url_or_domain(text: str, valid_tlds: set[str]) -> tuple[bool, str]:
    """
    Check if text qualifies as a URL or bare domain.
    Returns (is_valid, normalized_url).
    """
    if not text or not isinstance(text, str):
        return False, ""

    cand = text.strip(" '\"`<>")
    if not cand or len(cand) > 2048:
        return False, ""

    # Reject strings with whitespace or control characters
    if any(c in cand for c in " \t\r\n\x00"):
        return False, ""

    # If starts with scheme
    if cand.lower().startswith(("http://", "https://", "ftp://")):
        p = parse_url(cand)
        if p.effective_host and "INVALID_HOST" not in p.flags:
            return True, cand
        return False, ""

    if cand.startswith("//"):
        p = parse_url("http:" + cand)
        if p.effective_host and "INVALID_HOST" not in p.flags:
            return True, "http:" + cand
        return False, ""

    # Bare domain check
    host_part = re.split(r"[/?#]", cand, maxsplit=1)[0]
    if ":" in host_part:
        parts = host_part.split(":", 1)
        if not parts[1].isdigit():
            return False, ""
        host_part = parts[0]

    if not host_part or "." not in host_part:
        return False, ""

    labels = host_part.lower().split(".")
    if any(not lbl or not re.fullmatch(r"[a-zA-Z0-9-]+", lbl) for lbl in labels):
        return False, ""

    tld = labels[-1]
    if tld in valid_tlds:
        return True, cand

    return False, ""


def _try_decode_base64_url(token: str, valid_tlds: set[str]) -> tuple[str | None, str | None]:
    """
    Attempt to decode base64/base64url token.
    Must decode to >= 90% printable UTF-8 and contain :// or domain.tld.
    Returns: (extracted_url, full_decoded_text) or (None, None).
    """
    if not token or not (16 <= len(token) <= 4096):
        return None, None
    if not RE_BASE64_TOKEN.fullmatch(token):
        return None, None

    # Base64url normalization
    norm = token.replace("-", "+").replace("_", "/")
    padding = (4 - len(norm) % 4) % 4
    norm += "=" * padding

    try:
        raw_bytes = base64.b64decode(norm, validate=False)
    except Exception:
        return None, None

    try:
        decoded_text = raw_bytes.decode("utf-8")
    except Exception:
        return None, None

    if not decoded_text:
        return None, None

    # Check printable characters >= 90%
    printable_count = sum(1 for c in decoded_text if c.isprintable() or c in "\t\r\n")
    if printable_count / len(decoded_text) < 0.90:
        return None, None

    cand = decoded_text.strip()
    if "://" in cand:
        m = re.search(r"(?:https?|ftp)://[^\s'\"`<>]{3,2048}", cand, re.IGNORECASE)
        if m:
            extracted = m.group(0)
            is_valid, norm_url = _is_url_or_domain(extracted, valid_tlds)
            if is_valid:
                return norm_url, decoded_text
    else:
        is_valid, norm_url = _is_url_or_domain(cand, valid_tlds)
        if is_valid:
            return norm_url, decoded_text

        m = re.search(r"\b([a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,63}(?:/[^\s'\"`<>]*)?)\b", cand)
        if m:
            extracted = m.group(1)
            is_valid, norm_url = _is_url_or_domain(extracted, valid_tlds)
            if is_valid:
                return norm_url, decoded_text

    return None, None


def _try_decode_hex_url(token: str) -> str | None:
    """
    Attempt to decode even-length hex token >= 20 chars.
    Must decode to UTF-8 starting with 'http'.
    """
    if not token or len(token) < 20 or len(token) % 2 != 0:
        return None
    if not RE_HEX_TOKEN.fullmatch(token):
        return None

    try:
        raw_bytes = bytes.fromhex(token)
        decoded_text = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None

    if decoded_text.lower().startswith(("http://", "https://")):
        return decoded_text.strip()

    return None


def _is_trusted_redirector(effective_host: str, path: str, redirectors: dict[str, list[str]]) -> tuple[bool, list[str]]:
    """Check if host/path matches a known trusted redirector service."""
    if not effective_host:
        return False, []

    # Check exact host/path or stripped www host/path
    clean_host = effective_host.lower()
    if clean_host.startswith("www."):
        clean_host = clean_host[4:]

    host_path = f"{clean_host}{path}".rstrip("/")
    for redir_pattern, params in redirectors.items():
        pattern_norm = redir_pattern.rstrip("/")
        if host_path == pattern_norm or host_path.startswith(pattern_norm + "/"):
            return True, params
        if clean_host == pattern_norm:
            return True, params

    return False, []


def peel(
    parsed_or_raw: ParsedUrl | str,
    depth: int = 0,
    max_depth: int = MAX_DEPTH,
    seen: set[str] | None = None,
    total_decoded_chars: int = 0,
) -> PeelResult:
    """
    Peel layers of encoding (percent, base64, hex, open redirects) from URL.

    Guarantees:
      - Max recursion depth <= 4.
      - Max total decoded characters <= 4096.
      - Max 10 inner URLs discovered.
      - Loop detection prevents duplicate / cyclical peeling.
      - No network calls.
      - Informative Vietnamese description for each step.
    """
    if depth >= max_depth or total_decoded_chars >= MAX_DECODED_CHARS:
        return PeelResult()

    if seen is None:
        seen = set()

    if isinstance(parsed_or_raw, str):
        raw_url = parsed_or_raw
        parsed = parse_url(raw_url)
    else:
        parsed = parsed_or_raw
        raw_url = parsed.raw

    if raw_url in seen:
        return PeelResult()
    seen.add(raw_url)

    steps: list[ObfuscationStep] = []
    inner: list[Candidate] = []
    flags: list[str] = []

    valid_tlds = get_valid_tlds()
    redirectors = get_redirectors_config()

    is_trusted_redir, specific_params = _is_trusted_redirector(
        parsed.effective_host, parsed.path, redirectors
    )
    all_redirect_params = COMMON_REDIRECT_PARAMS | {p.lower() for p in specific_params}

    # (a) Percent-decode query & path up to 3 rounds
    current_query = parsed.query
    current_path = parsed.path

    if "%25" in current_query or "%25" in current_path:
        flags.append("DOUBLE_ENCODING")

    for round_idx in range(1, 4):
        unquoted_q = urllib.parse.unquote(current_query)
        unquoted_p = urllib.parse.unquote(current_path)

        if unquoted_q != current_query or unquoted_p != current_path:
            if "%25" in current_query or "%25" in current_path or round_idx > 1:
                if "DOUBLE_ENCODING" not in flags:
                    flags.append("DOUBLE_ENCODING")

            step_tech = "double_encoding" if ("DOUBLE_ENCODING" in flags and round_idx > 1) else "percent_host"
            before_str = current_query if current_query != unquoted_q else current_path
            after_str = unquoted_q if current_query != unquoted_q else unquoted_p

            steps.append(
                ObfuscationStep(
                    technique=step_tech,
                    detail_vi=f"Giải mã %xx lớp {round_idx}: URL được mã hóa percent-encoding",
                    before=before_str[:200],
                    after=after_str[:200],
                )
            )

            current_query = unquoted_q
            current_path = unquoted_p
        else:
            break

    # (b) Parameter extraction from both raw and unquoted query strings
    queries_to_scan = [parsed.query]
    if current_query != parsed.query:
        queries_to_scan.append(current_query)

    discovered_inners: list[tuple[str, str, str]] = []  # (url, via, before_token)

    for q_str in queries_to_scan:
        if not q_str:
            continue
        try:
            params = urllib.parse.parse_qsl(q_str, keep_blank_values=True)
        except Exception:
            continue

        for p_name, p_val in params:
            if not p_val or len(p_val) < 3:
                continue

            p_name_lower = p_name.lower()

            # 1. Check redirect param
            if p_name_lower in all_redirect_params:
                # Unquote parameter value up to 3 rounds
                val_unquoted = p_val
                for _ in range(3):
                    next_val = urllib.parse.unquote(val_unquoted)
                    if next_val == val_unquoted:
                        break
                    val_unquoted = next_val

                is_valid, norm_url = _is_url_or_domain(val_unquoted, valid_tlds)
                if is_valid:
                    discovered_inners.append((norm_url, f"redirect:{p_name}", f"{p_name}={p_val[:100]}"))

            # 2. Check base64 in query value
            extracted_b64, full_b64 = _try_decode_base64_url(p_val, valid_tlds)
            if extracted_b64:
                discovered_inners.append((extracted_b64, "base64", p_val[:100]))

            # 3. Check hex in query value
            extracted_hex = _try_decode_hex_url(p_val)
            if extracted_hex:
                discovered_inners.append((extracted_hex, "hex", p_val[:100]))

    # (c) Path segments inspection for base64 / hex
    path_segments = [seg for seg in parsed.path.split("/") if seg]
    for seg in path_segments:
        # Check base64 in path segment
        extracted_b64, full_b64 = _try_decode_base64_url(seg, valid_tlds)
        if extracted_b64:
            discovered_inners.append((extracted_b64, "base64", seg[:100]))

        # Check hex in path segment
        extracted_hex = _try_decode_hex_url(seg)
        if extracted_hex:
            discovered_inners.append((extracted_hex, "hex", seg[:100]))

    # Process discovered inner URLs
    seen_inners_this_round: set[str] = set()

    for inner_url, via_type, before_token in discovered_inners:
        if inner_url in seen_inners_this_round or inner_url in seen:
            continue
        seen_inners_this_round.add(inner_url)

        if len(inner) >= MAX_INNER_URLS or total_decoded_chars >= MAX_DECODED_CHARS:
            break

        flags.append("EMBEDDED_URL")

        if via_type.startswith("redirect:"):
            param_key = via_type.split(":", 1)[1]
            steps.append(
                ObfuscationStep(
                    technique="redirect_param",
                    detail_vi=f"Tham số chuyển hướng '{param_key}' chứa URL đích",
                    before=before_token,
                    after=inner_url[:200],
                )
            )

            # Check open redirect from trusted domain
            if is_trusted_redir:
                inner_parsed = parse_url(inner_url)
                if (
                    inner_parsed.effective_host
                    and inner_parsed.effective_host != parsed.effective_host
                    and inner_parsed.registrable_domain != parsed.registrable_domain
                ):
                    flags.append("OPEN_REDIRECT_TRUSTED")

        elif via_type == "base64":
            flags.append("BASE64_URL")
            steps.append(
                ObfuscationStep(
                    technique="base64_param",
                    detail_vi="Giải mã Base64 tìm thấy URL ẩn",
                    before=before_token,
                    after=inner_url[:200],
                )
            )

        elif via_type == "hex":
            flags.append("HEX_URL")
            steps.append(
                ObfuscationStep(
                    technique="hex_param",
                    detail_vi="Giải mã chuỗi Hex tìm thấy URL ẩn",
                    before=before_token,
                    after=inner_url[:200],
                )
            )

        candidate = Candidate(
            raw=inner_url,
            start=0,
            end=len(inner_url),
            source="embedded",
            via=via_type,
        )
        inner.append(candidate)
        total_decoded_chars += len(inner_url)

        # Recursive peeling
        if depth + 1 < max_depth and total_decoded_chars < MAX_DECODED_CHARS:
            child_result = peel(
                inner_url,
                depth=depth + 1,
                max_depth=max_depth,
                seen=seen,
                total_decoded_chars=total_decoded_chars,
            )
            steps.extend(child_result.steps)
            flags.extend(child_result.flags)
            for child_c in child_result.inner:
                if len(inner) < MAX_INNER_URLS and child_c.raw not in [c.raw for c in inner]:
                    inner.append(child_c)

    return PeelResult(
        steps=steps,
        inner=inner[:MAX_INNER_URLS],
        flags=list(dict.fromkeys(flags)),
    )
