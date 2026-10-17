from __future__ import annotations

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


def decode_idna_label(label: str) -> str:
    """Decode punycode label (e.g. 'xn--...') to Unicode."""
    if not label:
        return ""
    l_clean = label.lower().strip()
    if l_clean.startswith("xn--"):
        try:
            return idna.decode(l_clean).lower()
        except Exception:
            return l_clean
    return l_clean


def decode_idna_host(host: str) -> str:
    """Decode each label in host from punycode to Unicode."""
    if not host:
        return ""
    parts = host.split(".")
    return ".".join(decode_idna_label(p) for p in parts)


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
    """Check if label contains Cyrillic, Greek, fullwidth, or non-ASCII characters."""
    if not label:
        return False
    for c in label[:63]:
        if c in CONFUSABLE_UNICODE_CHARS or ord(c) > 127:
            return True
        name = unicodedata.name(c, "")
        if name.startswith(("CYRILLIC", "GREEK", "FULLWIDTH")):
            return True
    return False


def skeleton(
    label: str,
    replace_digits: bool = True,
    replace_lookalikes: bool = True,
) -> str:
    """
    Produce canonical skeleton of a domain label.
    1. Replace Vietnamese 'đ'/'Đ' -> 'd'
    2. NFKD decomposition (decomposes accents, converts fullwidth Latin to ASCII)
    3. Remove combining marks (category 'Mn' - strips all accents including ê, é, ô, ơ, ư, etc.)
    4. Cyrillic/Greek confusables -> Latin
    5. Lowercase
    6. Digits -> letters (0->o, 1->l, 3->e, 4->a, 5->s) if requested
    7. Multi-char lookalikes (rn->m, vv->w, cl->d) if requested
    8. Remove hyphens '-'
    Linear complexity, bounded length 63.
    """
    if not label:
        return ""
    bounded = label[:63]
    # Replace Vietnamese special letter d-stroke
    s = bounded.replace("đ", "d").replace("Đ", "d")
    # NFKD decomposes precomposed diacritics and converts fullwidth Latin to ASCII
    s = unicodedata.normalize("NFKD", s)
    # Strip combining marks (accents)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    # Lowercase
    s = s.lower()
    # Confusables mapping (Cyrillic and Greek)
    s = "".join(CONFUSABLES_MAP.get(c, c) for c in s)
    # Digits
    if replace_digits:
        s = "".join(DIGIT_MAP.get(c, c) for c in s)
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
        self.related_domain_map: dict[str, dict[str, Any]] = {}
        self.all_official_domains: set[str] = set()
        self.all_related_domains: set[str] = set()
        self.brand_keywords: list[tuple[dict[str, Any], str, bool]] = []

        for b in self.brands:
            b_short = {t.lower() for t in b.get("short_tokens", [])}
            for d in b.get("official_domains", []):
                d_low = d.lower().strip(".")
                self.official_domain_map[d_low] = b
                self.all_official_domains.add(d_low)

            for d in b.get("related_domains", []):
                d_low = d.lower().strip(".")
                self.related_domain_map[d_low] = b
                self.all_related_domains.add(d_low)

            for kw in b.get("keywords", []):
                kw_clean = kw.lower().strip()
                if kw_clean:
                    is_short = (kw_clean in b_short) or (len(kw_clean) < 5)
                    self.brand_keywords.append((b, kw_clean, is_short))

    def is_related(self, effective_host: str) -> tuple[bool, dict[str, Any] | None]:
        """
        Check if effective_host is an authorized related domain of a known brand.
        Returns: (is_related_bool, brand_dict_or_None)
        """
        if not effective_host:
            return False, None

        host = effective_host.lower().strip(" \t\r\n.")
        if not host:
            return False, None

        if host in self.platform_domains or any(host.endswith("." + plat) for plat in self.platform_domains):
            return False, None

        for rel_dom, brand in self.related_domain_map.items():
            if host == rel_dom or host.endswith("." + rel_dom):
                return True, brand

        return False, None

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
          - homoglyph: skeleton(token) == brand keyword with diacritics / confusables (any script).
          - tld_swap: registrable label matches brand exactly, but TLD differs from official/related.
          - typosquat: Damerau-Levenshtein <= 1 (len 5-10) or <= 2 (len >= 11) on individual
                       registrable tokens or merged adjacent tokens.
          - combosquat: token exact match or embedded brand keyword with other tokens.
          - subdomain_brand: brand keyword appears in subdomain prefix while registrable domain is different.
          - path_brand: brand keyword in path/query of an unofficial domain.
        Returns: {brand_id, display_name, technique, distance, official_domain} or None.
        """
        if not finding_host:
            return None

        # (a) Bounded DNS length: max 253 chars for host, max 63 chars per label
        bounded_host = finding_host[:253]
        bounded_host = ".".join(lbl[:63] for lbl in bounded_host.split("."))
        host = bounded_host.lower().strip(" \t\r\n.")
        if not host:
            return None

        # Decode IDNA host label by label into Unicode (capped 253 chars and 63 chars/label)
        unicode_host = decode_idna_host(host)[:253]
        unicode_host = ".".join(lbl[:63] for lbl in unicode_host.split("."))

        # 0. Check if host or unicode_host is official or authorized related domain
        is_off, _ = self.is_official(host)
        if is_off:
            return None
        is_rel, _ = self.is_related(host)
        if is_rel:
            return None
        if unicode_host != host:
            is_off_u, _ = self.is_official(unicode_host)
            if is_off_u:
                return None
            is_rel_u, _ = self.is_related(unicode_host)
            if is_rel_u:
                return None

        # Calculate registrable domain if not provided
        if not registrable_domain:
            registrable_domain = compute_registrable_domain(host)
        reg_bounded = (registrable_domain or "")[:253]
        reg_bounded = ".".join(lbl[:63] for lbl in reg_bounded.split("."))
        reg_dom = reg_bounded.lower().strip(".")
        unicode_reg_dom = decode_idna_host(reg_dom)[:253] if reg_dom else ""
        if unicode_reg_dom:
            unicode_reg_dom = ".".join(lbl[:63] for lbl in unicode_reg_dom.split("."))

        all_legit = self.all_official_domains | self.all_related_domains

        # Exclude legitimate official / related domains of ANY brand
        for d in (host, unicode_host, reg_dom, unicode_reg_dom):
            if d and (d in all_legit or any(d.endswith("." + legit) for legit in all_legit)):
                return None

        # 1. Subdomain brand check
        check_reg = unicode_reg_dom or reg_dom
        check_host = unicode_host or host
        if check_reg and check_host != check_reg and check_host.endswith("." + check_reg):
            sub_prefix = check_host[: -(len(check_reg) + 1)]
            sub_tokens = [t[:63] for t in re.split(r"[-._]+", sub_prefix) if t][:16]
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
        if check_reg:
            reg_main_label = check_reg.split(".")[0][:63]
        else:
            reg_main_label = check_host.split(".")[0][:63]

        # (b) Tokenize main label: max 16 tokens per label and max 16 adjacent token pairs
        raw_tokens_all = [t[:63] for t in re.split(r"[-.]+", reg_main_label) if t]
        raw_tokens = raw_tokens_all[:16]

        candidate_tokens: list[tuple[str, bool]] = []
        for t in raw_tokens:
            candidate_tokens.append((t, t == reg_main_label))

        # Merged adjacent tokens: max 16 pairs
        num_pairs = min(16, len(raw_tokens_all) - 1)
        for i in range(max(0, num_pairs)):
            pair = (raw_tokens_all[i] + raw_tokens_all[i + 1])[:63]
            candidate_tokens.append((pair, pair == reg_main_label.replace("-", "").replace(".", "")[:63]))

        if len(raw_tokens_all) >= 3:
            num_triples = min(16, len(raw_tokens_all) - 2)
            for i in range(max(0, num_triples)):
                triple = (raw_tokens_all[i] + raw_tokens_all[i + 1] + raw_tokens_all[i + 2])[:63]
                candidate_tokens.append((triple, triple == reg_main_label.replace("-", "").replace(".", "")[:63]))

        no_hyphens = reg_main_label.replace("-", "").replace(".", "")[:63]
        candidate_tokens.append((no_hyphens, True))
        candidate_tokens.append((reg_main_label[:63], True))

        # Deduplicate candidate tokens preserving order
        dedup_candidates: list[tuple[str, bool]] = []
        seen_cand_strings: set[str] = set()
        for tok_str, is_f in candidate_tokens:
            tok_b = tok_str[:63]
            if tok_b and tok_b not in seen_cand_strings:
                seen_cand_strings.add(tok_b)
                dedup_candidates.append((tok_b, is_f))
        candidate_tokens = dedup_candidates

        # 2. Homoglyph check across all candidate tokens and scripts (Cyrillic, Greek, fullwidth, Vietnamese IDN)
        for tok, is_full in candidate_tokens:
            tok_bounded = tok[:63]
            sk_no_repl = skeleton(tok_bounded, replace_digits=False, replace_lookalikes=False)
            sk_full = skeleton(tok_bounded, replace_digits=True, replace_lookalikes=True)
            for brand, kw, is_short in self.brand_keywords:
                # If skeleton without digits/lookalikes equals brand keyword, but the raw token is not pure ASCII kw:
                if sk_no_repl == kw and tok_bounded != kw:
                    return {
                        "brand_id": brand["brand_id"],
                        "display_name": brand["display_name"],
                        "technique": "homoglyph",
                        "distance": 0,
                        "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                    }
                # R2.7: For short brands (<= 4 chars, e.g. momo, zalo, acb, vib, mb),
                # compare skeleton(token) == keyword with full lookalikes (rn->m, 0->o, 1->l, vv->w, cl->d)
                if (is_short or len(kw) <= 4) and sk_full == kw and tok_bounded != kw:
                    return {
                        "brand_id": brand["brand_id"],
                        "display_name": brand["display_name"],
                        "technique": "homoglyph",
                        "distance": 0,
                        "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                    }

        # 3. Exact brand match: TLD Swap or Combosquat exact token
        for tok, is_full in candidate_tokens:
            for brand, kw, is_short in self.brand_keywords:
                if tok == kw:
                    if is_full:
                        off_list = [d.lower() for d in brand.get("official_domains", [])]
                        rel_list = [d.lower() for d in brand.get("related_domains", [])]
                        if reg_dom not in off_list and reg_dom not in rel_list and unicode_reg_dom not in off_list and unicode_reg_dom not in rel_list:
                            return {
                                "brand_id": brand["brand_id"],
                                "display_name": brand["display_name"],
                                "technique": "tld_swap",
                                "distance": 0,
                                "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                            }
                    else:
                        return {
                            "brand_id": brand["brand_id"],
                            "display_name": brand["display_name"],
                            "technique": "combosquat",
                            "distance": 0,
                            "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                        }

        # (c) Cache skeleton and Damerau-Levenshtein in a single analysis run
        sk_cache: dict[str, str] = {}
        dist_cache: dict[tuple[str, str], int] = {}

        def _get_sk(t: str) -> str:
            if t not in sk_cache:
                sk_cache[t] = skeleton(t, replace_digits=True, replace_lookalikes=True)
            return sk_cache[t]

        def _get_dist(s1: str, s2: str) -> int:
            k = (s1, s2)
            if k not in dist_cache:
                dist_cache[k] = damerau_levenshtein(s1, s2)
            return dist_cache[k]

        # 4. Typosquat check (Damerau-Levenshtein on tokens or merged adjacent tokens)
        for tok, is_full in candidate_tokens:
            tok_bounded = tok[:63]
            tok_sk = _get_sk(tok_bounded)

            for brand, kw, is_short in self.brand_keywords:
                if is_short or len(kw) < 4:
                    continue
                if tok_bounded == kw:
                    continue

                n_len = max(len(tok_bounded), len(kw))
                if n_len < 5:
                    continue

                max_allowed_dist = 2 if n_len >= 11 else 1
                diff_raw = abs(len(tok_bounded) - len(kw))
                diff_sk = abs(len(tok_sk) - len(kw))

                # Cheap pre-filtering: compute Damerau-Levenshtein only when |len - len(kw)| <= threshold
                if diff_raw > max_allowed_dist and diff_sk > max_allowed_dist:
                    continue

                d_raw = _get_dist(tok_bounded, kw) if diff_raw <= max_allowed_dist else (max_allowed_dist + 1)
                d_sk = _get_dist(tok_sk, kw) if diff_sk <= max_allowed_dist else (max_allowed_dist + 1)
                dist = d_raw if (d_sk == 0 and tok_bounded != kw) else min(d_raw, d_sk)

                is_typo = False
                if 5 <= n_len <= 10 and dist == 1:
                    is_typo = True
                elif n_len >= 11 and 1 <= dist <= 2:
                    is_typo = True

                if is_typo:
                    if reg_dom not in all_legit and unicode_reg_dom not in all_legit:
                        return {
                            "brand_id": brand["brand_id"],
                            "display_name": brand["display_name"],
                            "technique": "typosquat",
                            "distance": dist,
                            "official_domain": brand["official_domains"][0] if brand["official_domains"] else "",
                        }

        # 5. Combosquat check (Brand keyword embedded with hyphens/dots in host/registrable)
        host_tokens = [t for t in re.split(r"[-._]+", check_host) if t]
        reg_tokens = [t for t in re.split(r"[-._]+", reg_main_label) if t]
        all_tokens = set(host_tokens + reg_tokens)

        for brand, kw, is_short in self.brand_keywords:
            matched = False
            if is_short:
                # Short tokens MUST match as an exact token in multi-token host
                if kw in all_tokens:
                    if check_host != kw and reg_main_label != kw:
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
