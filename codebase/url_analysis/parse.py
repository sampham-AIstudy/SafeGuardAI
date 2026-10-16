from __future__ import annotations

import functools
import ipaddress
import re
import unicodedata
import urllib.parse
from typing import Any

import idna

from codebase.url_analysis.models import ParsedUrl
from codebase.url_analysis.normalize import load_url_lists

MAX_URL_LEN = 2048

# Linear regex patterns without nested quantifiers or '.*'
RE_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]{0,31}):")
RE_DELIMITERS = re.compile(r"[/?#]")
RE_STANDARD_IPV4 = re.compile(
    r"^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    r"(\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3}$"
)


@functools.lru_cache(maxsize=1)
def get_combined_suffixes() -> set[str]:
    """Return set of combined multi-level suffixes and free hosting platforms."""
    lists = load_url_lists()
    suffixes = {s.lower() for s in lists.get("multi_level_suffixes", [])}
    hosting = {h.lower() for h in lists.get("free_hosting", [])}
    return suffixes | hosting


def _is_numeric_part(part: str) -> bool:
    """Check if string is a numeric IPv4 part in hex, octal, or decimal."""
    if not part:
        return False
    plow = part.lower()
    if plow.startswith("0x") and len(plow) > 2:
        return all(c in "0123456789abcdef" for c in plow[2:])
    if part.startswith("0") and len(part) > 1:
        return all(c in "01234567" for c in part)
    return part.isdigit()


def _parse_numeric_part(part: str) -> int | None:
    """Parse numeric IPv4 component."""
    try:
        plow = part.lower()
        if plow.startswith("0x") and len(plow) > 2:
            return int(plow[2:], 16)
        if part.startswith("0") and len(part) > 1 and all(c in "01234567" for c in part):
            return int(part, 8)
        if part.isdigit():
            return int(part, 10)
    except Exception:
        return None
    return None


def _parse_whatwg_ipv4(host: str) -> tuple[bool, str | None, bool]:
    """
    Parse host as a WHATWG IPv4 address.
    Returns: (is_ipv4_attempt, dotted_str_or_none, is_obfuscated)
    """
    if not host:
        return False, None, False
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        if all(_is_numeric_part(p) for p in parts):
            return True, None, False
        return False, None, False

    for p in parts:
        if not _is_numeric_part(p):
            return False, None, False

    parsed_nums: list[int] = []
    is_obfuscated = False

    if len(parts) != 4:
        is_obfuscated = True
    else:
        for p in parts:
            if p.lower().startswith("0x") or (p.startswith("0") and len(p) > 1):
                is_obfuscated = True
                break

    for p in parts:
        num = _parse_numeric_part(p)
        if num is None or num < 0:
            return True, None, False
        parsed_nums.append(num)

    n = len(parsed_nums)
    if n == 1:
        if parsed_nums[0] > 0xFFFFFFFF:
            return True, None, False
        val = parsed_nums[0]
    elif n == 2:
        if parsed_nums[0] > 255 or parsed_nums[1] > 0xFFFFFF:
            return True, None, False
        val = (parsed_nums[0] << 24) + parsed_nums[1]
    elif n == 3:
        if parsed_nums[0] > 255 or parsed_nums[1] > 255 or parsed_nums[2] > 0xFFFF:
            return True, None, False
        val = (parsed_nums[0] << 24) + (parsed_nums[1] << 16) + parsed_nums[2]
    elif n == 4:
        if any(x > 255 for x in parsed_nums):
            return True, None, False
        val = (
            (parsed_nums[0] << 24)
            + (parsed_nums[1] << 16)
            + (parsed_nums[2] << 8)
            + parsed_nums[3]
        )
    else:
        return True, None, False

    try:
        dotted = str(ipaddress.IPv4Address(val))
    except Exception:
        return True, None, False

    if not is_obfuscated and not RE_STANDARD_IPV4.fullmatch(host):
        is_obfuscated = True

    return True, dotted, is_obfuscated


def _get_script_group(char: str) -> str:
    """Return script classification for homoglyph / mixed script detection."""
    if "a" <= char <= "z" or "A" <= char <= "Z":
        return "LATIN"
    if "0" <= char <= "9" or char in "-_":
        return "COMMON"
    name = unicodedata.name(char, "")
    if not name:
        return "UNKNOWN"
    first = name.split()[0]
    if first in ("LATIN", "CYRILLIC", "GREEK"):
        return first
    return "OTHER"


def _compute_registrable_domain(
    host: str,
    combined_suffixes: set[str],
) -> str:
    """Calculate registrable domain using public suffixes and free hosting list."""
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 1:
        return host

    max_suffix_labels = 3
    for k in range(min(len(labels), max_suffix_labels), 1, -1):
        suffix_candidate = ".".join(labels[-k:])
        if suffix_candidate in combined_suffixes:
            if len(labels) > k:
                return ".".join(labels[-(k + 1):])
            else:
                return suffix_candidate

    return ".".join(labels[-2:])


def compute_registrable_domain(host: str) -> str:
    """Public helper to calculate registrable domain for a host."""
    return _compute_registrable_domain(host, get_combined_suffixes())


def parse_url(raw: str) -> ParsedUrl:
    """
    Parse a URL simulating browser (WHATWG) behavior safely and linearly.

    Guarantees:
      - Never raises any exception on any input.
      - Enforces linear regexes with length cap at 2048.
      - WHATWG backslash conversion and BACKSLASH_CONFUSION detection.
      - Userinfo parsed according to LAST '@' in authority.
      - Host percent-decoding (ENCODED_HOST).
      - WHATWG IPv4 normalization and obfuscation detection.
      - IDNA encoding (PUNYCODE_HOST, INVALID_IDN, MIXED_SCRIPT).
      - Registrable domain and deep subdomain detection.
    """
    flags: list[str] = []

    if raw is None or not isinstance(raw, str):
        return ParsedUrl(
            raw=str(raw or ""),
            scheme="",
            userinfo="",
            display_host="",
            effective_host="",
            effective_host_unicode="",
            port=None,
            path="",
            query="",
            fragment="",
            registrable_domain="",
            ip=None,
            flags=["INVALID_HOST"],
        )

    # 1. Truncate long URLs
    raw_str = raw
    if len(raw_str) > MAX_URL_LEN:
        raw_str = raw_str[:MAX_URL_LEN]
        flags.append("LONG_URL")

    # 2. Strip leading/trailing whitespace, tabs, newlines
    cleaned = raw_str.strip(" \t\r\n")

    # Embedded null bytes or control characters
    if "\x00" in cleaned:
        flags.append("INVALID_HOST")

    # Remove internal tabs and newlines per WHATWG
    cleaned_no_newlines = cleaned.replace("\t", "").replace("\r", "").replace("\n", "")

    # 3. Extract scheme
    scheme_match = RE_SCHEME.match(cleaned_no_newlines)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        rest = cleaned_no_newlines[scheme_match.end():]
    else:
        scheme = ""
        rest = cleaned_no_newlines

    # Special handling for data:, javascript:, vbscript:
    if scheme in ("data", "javascript", "vbscript"):
        flags.append("DATA_OR_JS_URI")
        return ParsedUrl(
            raw=raw,
            scheme=scheme,
            userinfo="",
            display_host="",
            effective_host="",
            effective_host_unicode="",
            port=None,
            path=rest,
            query="",
            fragment="",
            registrable_domain="",
            ip=None,
            flags=list(dict.fromkeys(flags)),
        )

    # 4. WHATWG backslash conversion for special schemes and schemeless URLs
    has_backslash = "\\" in rest
    urllib_host = ""
    try:
        check_url = cleaned_no_newlines if scheme else f"http://{cleaned_no_newlines}"
        urllib_host = (urllib.parse.urlsplit(check_url).hostname or "").lower()
    except Exception:
        urllib_host = ""

    if scheme in ("http", "https", "ftp", "ws", "wss", ""):
        if has_backslash:
            rest = rest.replace("\\", "/")

    # 5. Separate authority from path/query/fragment
    if rest.startswith("//"):
        rest = rest[2:]

    delim_match = RE_DELIMITERS.search(rest)
    if delim_match:
        idx = delim_match.start()
        authority = rest[:idx]
        tail = rest[idx:]
    else:
        authority = rest
        tail = ""

    if "#" in tail:
        path_and_query, fragment = tail.split("#", 1)
    else:
        path_and_query, fragment = tail, ""

    if "?" in path_and_query:
        path, query = path_and_query.split("?", 1)
    else:
        path, query = path_and_query, ""

    # 6. Parse userinfo and host:port in authority
    userinfo = ""
    host_port = authority
    display_host = ""

    if "@" in authority:
        userinfo, host_port = authority.rsplit("@", 1)
        flags.append("USERINFO_PRESENT")

        # Determine display_host if userinfo mimics a domain
        user_host_cand = userinfo.split(":", 1)[0]
        if "." in user_host_cand and any(c.isalpha() for c in user_host_cand):
            display_host = user_host_cand.lower()

    # 7. Separate host and port from host_port
    raw_host = host_port
    port_str = ""

    if host_port.startswith("["):
        closing_idx = host_port.find("]")
        if closing_idx != -1:
            raw_host = host_port[: closing_idx + 1]
            port_part = host_port[closing_idx + 1 :]
            if port_part.startswith(":"):
                port_str = port_part[1:]
        else:
            raw_host = host_port
            flags.append("INVALID_HOST")
    else:
        if ":" in host_port:
            parts = host_port.split(":", 1)
            raw_host = parts[0]
            port_str = parts[1]

    if not display_host:
        display_host = raw_host.lower()

    # 8. Parse port
    port: int | None = None
    if port_str:
        if port_str.isdigit():
            try:
                port_val = int(port_str)
                if 0 < port_val <= 65535:
                    if (scheme == "http" and port_val == 80) or \
                       (scheme == "https" and port_val == 443) or \
                       (not scheme and port_val in (80, 443)):
                        port = None
                    else:
                        port = port_val
                        if port_val not in (80, 443):
                            flags.append("NON_STANDARD_PORT")
                else:
                    flags.append("INVALID_HOST")
            except Exception:
                flags.append("INVALID_HOST")
        else:
            flags.append("INVALID_HOST")

    # 9. Percent-decode host
    if "%" in raw_host:
        try:
            decoded_raw_host = urllib.parse.unquote(raw_host)
            if decoded_raw_host != raw_host:
                flags.append("ENCODED_HOST")
                raw_host = decoded_raw_host
        except Exception:
            pass

    host = raw_host.lower()

    # Check for invalid characters or empty host
    if not host or any(c in host for c in " \t\r\n\x00/\\?#@"):
        flags.append("INVALID_HOST")

    # 10. Check IPv6
    ip: str | None = None
    effective_host = ""
    effective_host_unicode = ""
    registrable_domain = ""

    if host.startswith("[") and host.endswith("]"):
        try:
            v6_obj = ipaddress.IPv6Address(host[1:-1])
            ip = str(v6_obj)
            effective_host = f"[{v6_obj}]"
            effective_host_unicode = f"[{v6_obj}]"
            flags.append("IP_HOST")
        except Exception:
            flags.append("INVALID_HOST")
            effective_host = host
            effective_host_unicode = host

    else:
        # 11. Check WHATWG IPv4
        is_ipv4_attempt, dotted_ip, is_obfuscated = _parse_whatwg_ipv4(host)
        if is_ipv4_attempt:
            if dotted_ip is not None:
                ip = dotted_ip
                effective_host = dotted_ip
                effective_host_unicode = dotted_ip
                flags.append("IP_HOST")
                if is_obfuscated:
                    flags.append("IP_OBFUSCATED")
            else:
                flags.append("INVALID_HOST")
                effective_host = host
                effective_host_unicode = host
        else:
            # 12. Host is domain name
            # Check mixed script
            labels = host.split(".")
            for label in labels:
                scripts: set[str] = set()
                # If label is punycode, decode it first for script detection
                label_to_check = label
                if label.startswith("xn--"):
                    try:
                        label_to_check = idna.decode(label)
                    except Exception:
                        pass
                for ch in label_to_check:
                    grp = _get_script_group(ch)
                    if grp in ("LATIN", "CYRILLIC", "GREEK"):
                        scripts.add(grp)
                if "LATIN" in scripts and ("CYRILLIC" in scripts or "GREEK" in scripts):
                    flags.append("MIXED_SCRIPT")
                    break

            # IDNA encoding per label
            encoded_labels: list[str] = []
            unicode_labels: list[str] = []
            has_punycode = False
            has_invalid_idn = False

            for label in labels:
                if not label:
                    encoded_labels.append(label)
                    unicode_labels.append(label)
                    continue

                if label.startswith("xn--"):
                    has_punycode = True
                    encoded_labels.append(label)
                    try:
                        unicode_labels.append(idna.decode(label))
                    except Exception:
                        unicode_labels.append(label)
                else:
                    is_ascii = all(ord(c) < 128 for c in label)
                    if is_ascii:
                        encoded_labels.append(label)
                        unicode_labels.append(label)
                    else:
                        try:
                            enc = idna.encode(label, uts46=True, transitional=False).decode("ascii")
                            encoded_labels.append(enc)
                            unicode_labels.append(label)
                            has_punycode = True
                        except Exception:
                            has_invalid_idn = True
                            encoded_labels.append(label)
                            unicode_labels.append(label)

            if has_invalid_idn:
                flags.append("INVALID_IDN")
            if has_punycode:
                flags.append("PUNYCODE_HOST")

            effective_host = ".".join(encoded_labels)
            effective_host_unicode = ".".join(unicode_labels)

            # Compute registrable domain
            combined_suffixes = get_combined_suffixes()
            registrable_domain = _compute_registrable_domain(effective_host, combined_suffixes)

            # Check deep subdomain (>= 4 labels in subdomain portion)
            if effective_host and registrable_domain:
                if effective_host != registrable_domain and effective_host.endswith("." + registrable_domain):
                    sub_part = effective_host[: -len(registrable_domain) - 1]
                    sub_labels = [p for p in sub_part.split(".") if p]
                    if len(sub_labels) >= 4:
                        flags.append("DEEP_SUBDOMAIN")

            # Check INVALID_TLD
            if effective_host and "." in effective_host:
                tld_cand = effective_host.split(".")[-1].lower()
                valid_tlds = {t.lower() for t in load_url_lists().get("valid_tlds", [])}
                if valid_tlds and tld_cand not in valid_tlds and not tld_cand.isdigit():
                    flags.append("INVALID_TLD")

    # 13. Backslash confusion check
    if has_backslash:
        if effective_host != urllib_host:
            flags.append("BACKSLASH_CONFUSION")

    # 14. Validate effective host
    if not effective_host or any(c in effective_host for c in " \t\r\n\x00/\\?#@%"):
        if "INVALID_HOST" not in flags:
            flags.append("INVALID_HOST")
    elif not ip and not (effective_host.startswith("[") and effective_host.endswith("]")):
        # Validate domain characters and DNS label constraints
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", effective_host):
            if "INVALID_HOST" not in flags:
                flags.append("INVALID_HOST")
        else:
            host_labels = effective_host.split(".")
            if any(len(lbl) > 63 for lbl in host_labels) or len(effective_host) > 253:
                if "INVALID_HOST" not in flags:
                    flags.append("INVALID_HOST")

    return ParsedUrl(
        raw=raw,
        scheme=scheme,
        userinfo=userinfo,
        display_host=display_host,
        effective_host=effective_host,
        effective_host_unicode=effective_host_unicode,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        registrable_domain=registrable_domain,
        ip=ip,
        flags=list(dict.fromkeys(flags)),
    )
