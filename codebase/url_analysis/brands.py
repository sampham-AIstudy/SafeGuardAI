from __future__ import annotations

import functools
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

import idna

from codebase.url_analysis.parse import compute_registrable_domain

# Confusables mapping: Cyrillic and Greek characters to ASCII Latin
CONFUSABLES_MAP: dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0445": "x",  # х
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u0443": "y",  # у
    "\u043a": "k",  # к
    "\u0455": "s",  # ѕ
    "\u0437": "z",  # з
    "\u0432": "b",  # в
    "\u043c": "m",  # м
    "\u043d": "h",  # н
    "\u0442": "t",  # т
    "\u0433": "r",  # г
    "\u043f": "n",  # п
    # Cyrillic uppercase
    "\u0410": "a",  # А
    "\u0412": "b",  # В
    "\u0415": "e",  # Е
    "\u041a": "k",  # К
    "\u041c": "m",  # М
    "\u041d": "h",  # Н
    "\u041e": "o",  # О
    "\u0420": "p",  # Р
    "\u0421": "c",  # С
    "\u0422": "t",  # Т
    "\u0425": "x",  # Х
    "\u0406": "i",  # І
    "\u0408": "j",  # Ј
    # Greek lowercase
    "\u03bf": "o",  # ο
    "\u03bd": "v",  # ν
    "\u03b1": "a",  # α
    "\u03b5": "e",  # ε
    "\u03b9": "i",  # ι
    "\u03ba": "k",  # κ
    "\u03c1": "p",  # ρ
    "\u03c4": "t",  # τ
    "\u03c5": "u",  # υ
    "\u03c7": "x",  # χ
    "\u03b7": "n",  # η
    "\u03bc": "u",  # μ
    "\u03c9": "w",  # ω
    # Greek uppercase
    "\u0391": "a",  # Α
    "\u0392": "b",  # Β
    "\u0395": "e",  # Ε
    "\u0396": "z",  # Ζ
    "\u0397": "h",  # Η
    "\u0399": "i",  # Ι
    "\u039a": "k",  # Κ
    "\u039c": "m",  # Μ
    "\u039d": "n",  # Ν
    "\u039f": "o",  # Ο
    "\u03a1": "p",  # Ρ
    "\u03a4": "t",  # Τ
    "\u03a5": "y",  # Υ
    "\u03a7": "x",  # Χ
}

CONFUSABLE_UNICODE_CHARS: set[str] = set(CONFUSABLES_MAP.keys())

DIGIT_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
}

LOOKALIKE_SEQS: list[tuple[str, str]] = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
]


def strip_vietnamese_diacritics(text: str) -> str:
    """Normalize Vietnamese diacritics including đ -> d."""
    if not text:
        return ""
    # Map đ/Đ
    s = text.replace("đ", "d").replace("Đ", "d")
    # Decompose and remove combining marks
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    return unicodedata.normalize("NFC", s)


def has_confusable_unicode(label: str) -> bool:
    """Check if label contains Cyrillic or Greek confusables."""
    if not label:
        return False
    for c in label[:63]:
        if c in CONFUSABLE_UNICODE_CHARS:
            return True
        name = unicodedata.name(c, "")
        if name.startswith(("CYRILLIC", "GREEK")):
            return True
    return False


def skeleton(
    label: str,
    replace_digits: bool = True,
    replace_lookalikes: bool = True,
) -> str:
    """
    Produce canonical skeleton of a domain label.
    1. NFKC normalization
    2. Cyrillic/Greek confusables -> Latin
    3. Digits -> letters (0->o, 1->l, 3->e, 4->a, 5->s) if requested
    4. Multi-char lookalikes (rn->m, vv->w, cl->d) if requested
    5. Strip Vietnamese diacritics (đ->d)
    6. Lowercase
    7. Remove hyphens '-'
    Linear complexity, bounded length 63.
    """
    if not label:
        return ""
    bounded = label[:63]
    # NFKC
    s = unicodedata.normalize("NFKC", bounded)
    # Vietnamese diacritics
    s = strip_vietnamese_diacritics(s)
    # Lowercase
    s = s.lower()
    # Confusables mapping
    res = []
    for c in s:
        res.append(CONFUSABLES_MAP.get(c, c))
    s = "".join(res)
    # Digits
    if replace_digits:
        res_d = []
        for c in s:
            res_d.append(DIGIT_MAP.get(c, c))
        s = "".join(res_d)
    # Multi-char lookalikes
    if replace_lookalikes:
        for seq, repl in LOOKALIKE_SEQS:
            s = s.replace(seq, repl)
    # Remove hyphens
    s = s.replace("-", "")
    return s


def damerau_levenshtein(s1: str, s2: str) -> int:
    """
    Compute Damerau-Levenshtein distance between s1 and s2 (bounded to length 63).
    Supports insertion, deletion, substitution, and transposition of adjacent characters.
    """
    s1 = s1[:63]
    s2 = s2[:63]
    len1, len2 = len(s1), len(s2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1
    if s1 == s2:
        return 0

    inf = len1 + len2
    da: dict[str, int] = {}
    d = [[0] * (len2 + 2) for _ in range(len1 + 2)]

    d[0][0] = inf
    for i in range(len1 + 1):
        d[i + 1][0] = inf
        d[i + 1][1] = i
    for j in range(len2 + 1):
        d[0][j + 1] = inf
        d[1][j + 1] = j

    for i in range(1, len1 + 1):
        db = 0
        for j in range(1, len2 + 1):
            k = da.get(s2[j - 1], 0)
            l = db
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            if cost == 0:
                db = j
            d[i + 1][j + 1] = min(
                d[i][j + 1] + 1,       # deletion
                d[i + 1][j] + 1,       # insertion
                d[i][j] + cost,        # substitution
                d[k][l] + (i - k - 1) + 1 + (j - l - 1),  # transposition
            )
        da[s1[i - 1]] = i

    return d[len1 + 1][len2 + 1]


class BrandCatalog:
    """
    Catalog of Vietnamese Brands and Impersonation Analysis.
    Never flags platform_domains (e.g. sites.google.com, facebook.com) as official.
    """

    def __init__(
        self,
        brands: list[dict[str, Any]] | None = None,
        platform_domains: list[str] | set[str] | None = None,
    ):
        self.brands: list[dict[str, Any]] = brands or []
        self.platform_domains: set[str] = set(platform_domains or [])
        self._init_lookups()

    @classmethod
    def load(cls, path: str | Path | None = None) -> BrandCatalog:
        """Load BrandCatalog from vn_brands.json."""
        if path is None:
            path = Path(__file__).resolve().parent.parent / "knowledge_base" / "vn_brands.json"
        p = Path(path)
        if not p.exists():
            return cls([], [])

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            return cls(brands=data, platform_domains=[])
        elif isinstance(data, dict):
            brands = data.get("brands", [])
            platform_domains = data.get("platform_domains", [])
            return cls(brands=brands, platform_domains=platform_domains)
        return cls([], [])

    def _init_lookups(self) -> None:
        """Build fast lookup tables."""
        self.official_domain_map: dict[str, dict[str, Any]] = {}
        self.all_official_domains: set[str] = set()
        self.brand_keywords: list[tuple[dict[str, Any], str, bool]] = []

        for b in self.brands:
            b_short = {t.lower() for t in b.get("short_tokens", [])}
            for d in b.get("official_domains", []):
                d_low = d.lower().strip(".")
                self.official_domain_map[d_low] = b
                self.all_official_domains.add(d_low)

            for kw in b.get("keywords", []):
                kw_clean = kw.lower().strip()
                if kw_clean:
                    is_short = (kw_clean in b_short) or (len(kw_clean) < 5)
                    self.brand_keywords.append((b, kw_clean, is_short))

    def is_official(self, effective_host: str) -> tuple[bool, dict[str, Any] | None]:
        """
        Check if effective_host is an official domain or subdomain of a known brand.
        Rules:
          - Exact match against official_domains or subdomains of official_domains.
          - platform_domains are NEVER official.
          - Any '*.gov.vn' is classified as 'gov_generic' if not matched to a specific brand.
        Returns: (is_official_bool, brand_dict_or_None)
        """
        if not effective_host:
            return False, None

        host = effective_host.lower().strip(" \t\r\n.")
        if not host:
            return False, None

        # 1. Platform domains can NEVER be official
        if host in self.platform_domains or any(host.endswith("." + plat) for plat in self.platform_domains):
            return False, None

        # 2. Check official domains of registered brands
        for off_dom, brand in self.official_domain_map.items():
            if host == off_dom or host.endswith("." + off_dom):
                return True, brand

        # 3. Check *.gov.vn for gov_generic
        if host == "gov.vn" or host.endswith(".gov.vn"):
            return True, {
                "brand_id": "gov_generic",
                "display_name": "Cổng thông tin / Dịch vụ công Chính phủ",
                "category": "gov",
                "official_domains": ["gov.vn"],
                "keywords": ["gov"],
                "short_tokens": ["gov"],
                "verified": True,
                "source_url": "https://gov.vn",
            }

        return False, None

    def brand_match(
        self,
        finding_host: str,
        registrable_domain: str | None = None,
        path: str = "",
        query: str = "",
    ) -> dict[str, Any] | None:
        """
        Analyze whether finding_host or its path/query impersonates a brand.
        Techniques:
          - homoglyph: skeleton(label) == brand keyword with confusable unicode chars.
          - typosquat: Damerau-Levenshtein <= 1 (len 5-8) or <= 2 (len >= 9) on registrable label,
                       excluding official domains of other brands.
          - tld_swap: registrable label matches brand exactly, but TLD differs from official.
          - combosquat: host split by [-.] contains brand keyword (short tokens only match exact token).
          - subdomain_brand: brand keyword appears in subdomain prefix while registrable domain is different.
          - path_brand: brand keyword in path/query of an unofficial domain.
        Returns: {brand_id, display_name, technique, distance, official_domain} or None.
        """
        if not finding_host:
            return None

        host = finding_host.lower().strip(" \t\r\n.")
        if not host:
            return None

        # If host is official, it is not an impersonation attack
        is_off, _ = self.is_official(host)
        if is_off:
            return None

        # Decode IDNA if punycode
        if "xn--" in host:
            try:
                unicode_host = idna.decode(host).lower()
            except Exception:
                unicode_host = host
        else:
            unicode_host = host

        # Calculate registrable domain if not provided
        if not registrable_domain:
            registrable_domain = compute_registrable_domain(host)
        reg_dom = (registrable_domain or "").lower().strip(".")

        # If registrable domain is official for another brand, do not flag as typosquat/spoof
        if reg_dom and reg_dom in self.all_official_domains:
            return None

        # 1. Subdomain brand check
        if reg_dom and host != reg_dom and host.endswith("." + reg_dom):
            sub_prefix = host[: -(len(reg_dom) + 1)]
            sub_tokens = [t for t in re.split(r"[-._]+", sub_prefix) if t]
            for brand, kw, is_short in self.brand_keywords:
                matched = False
                if is_short:
                    if kw in sub_tokens:
                        matched = True
                else:
                    if any(kw in tok for tok in sub_tokens) or (kw in sub_prefix):
                        matched = True
                if matched:
                    return {
                        "brand_id": brand["brand_id"],
                        "display_name": brand["display_name"],
                        "technique": "subdomain_brand",
                        "distance": 0,
                        "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                    }

        # Extract main label of registrable domain
        if reg_dom:
            reg_labels = reg_dom.split(".")
            reg_main_label = reg_labels[0]
        else:
            reg_main_label = host.split(".")[0]

        if "xn--" in host and "xn--" in reg_dom:
            try:
                u_reg = idna.decode(reg_dom).lower()
                u_reg_main_label = u_reg.split(".")[0]
            except Exception:
                u_reg_main_label = reg_main_label
        else:
            u_reg_main_label = unicode_host.split(".")[0] if unicode_host else reg_main_label

        # 2. Homoglyph check (Unicode confusables from Cyrillic / Greek)
        if has_confusable_unicode(u_reg_main_label):
            u_sk = skeleton(u_reg_main_label, replace_digits=False, replace_lookalikes=False)
            for brand, kw, _ in self.brand_keywords:
                if u_sk == kw:
                    return {
                        "brand_id": brand["brand_id"],
                        "display_name": brand["display_name"],
                        "technique": "homoglyph",
                        "distance": 0,
                        "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                    }

        # 3. TLD Swap check (Exact brand match in main label, but different TLD)
        for brand, kw, _ in self.brand_keywords:
            if reg_main_label == kw:
                if reg_dom and reg_dom not in [d.lower() for d in brand.get("official_domains", [])]:
                    return {
                        "brand_id": brand["brand_id"],
                        "display_name": brand["display_name"],
                        "technique": "tld_swap",
                        "distance": 0,
                        "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                    }

        # 4. Typosquat check (Damerau-Levenshtein <= 1 or <= 2 on registrable label)
        lbl = reg_main_label[:63]
        lbl_sk = skeleton(lbl, replace_digits=True, replace_lookalikes=True)
        for brand, kw, is_short in self.brand_keywords:
            if abs(len(lbl) - len(kw)) > 2 or len(kw) < 4:
                continue

            # Check Levenshtein distance on raw label and lookalike-normalized label
            d_raw = damerau_levenshtein(lbl, kw)
            d_sk = damerau_levenshtein(lbl_sk, kw)
            dist = d_raw if (d_sk == 0 and lbl != kw) else min(d_raw, d_sk)

            n_len = max(len(lbl), len(kw))
            is_typo = False
            if 5 <= n_len <= 8 and dist == 1:
                is_typo = True
            elif n_len >= 9 and 1 <= dist <= 2:
                is_typo = True

            if is_typo:
                # Exclude official domains of ANY brand
                if reg_dom not in self.all_official_domains:
                    return {
                        "brand_id": brand["brand_id"],
                        "display_name": brand["display_name"],
                        "technique": "typosquat",
                        "distance": dist,
                        "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                    }

        # 5. Combosquat check (Brand keyword embedded with hyphens/dots in host/registrable)
        host_tokens = [t for t in re.split(r"[-._]+", host) if t]
        reg_tokens = [t for t in re.split(r"[-._]+", reg_main_label) if t]
        all_tokens = set(host_tokens + reg_tokens)

        for brand, kw, is_short in self.brand_keywords:
            matched = False
            if is_short:
                # Short tokens MUST match as an exact token
                if kw in all_tokens:
                    matched = True
            else:
                # Longer brands (>= 5 chars) match as token or substring in tokens/reg_main_label
                if any(kw in tok for tok in host_tokens) or (kw in reg_main_label):
                    matched = True

            if matched:
                return {
                    "brand_id": brand["brand_id"],
                    "display_name": brand["display_name"],
                    "technique": "combosquat",
                    "distance": 0,
                    "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                }

        # 6. Path brand check (Brand in path/query of an unofficial domain)
        if path or query:
            target_str = (path + " " + query).lower()
            path_tokens = set(re.split(r"[^a-zA-Z0-9]+", target_str))
            for brand, kw, is_short in self.brand_keywords:
                matched = False
                if is_short:
                    if kw in path_tokens:
                        matched = True
                else:
                    if kw in target_str or kw in path_tokens:
                        matched = True

                if matched:
                    return {
                        "brand_id": brand["brand_id"],
                        "display_name": brand["display_name"],
                        "technique": "path_brand",
                        "distance": 0,
                        "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                    }

        return None
