from __future__ import annotations

import csv
import json
import threading
from pathlib import Path
from typing import Any

from codebase.url_analysis.models import ParsedUrl
from codebase.url_analysis.normalize import load_url_lists
from codebase.url_analysis.parse import compute_registrable_domain

# Known sample test phishing domains (synthetic)
DEFAULT_SAMPLE_PHISH_HOSTS: set[str] = {
    "vcb-verify.xyz",
    "vcb-secure.xyz",
    "evil-vcb.top",
    "shopee-hoantien.top",
}

_cache_lock = threading.Lock()
_dataset_blacklist_cache: dict[tuple[str, tuple[str, ...]], PhishBlacklist] = {}


def _get_platform_and_free_hosting() -> set[str]:
    """Return lowercase set of free hosting and platform domains to exclude from host/registrable blacklist."""
    lists = load_url_lists()
    free_hosts = {h.lower().strip(".") for h in lists.get("free_hosting", [])}

    # Also load from vn_brands.json if available
    kb_path = Path(__file__).resolve().parent.parent / "knowledge_base" / "vn_brands.json"
    if kb_path.exists():
        try:
            with open(kb_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                free_hosts.update(p.lower().strip(".") for p in data.get("platform_domains", []))
        except Exception:
            pass

    # Ensure core platforms and subdomains are present
    free_hosts.update({
        "facebook.com",
        "fb.com",
        "instagram.com",
        "google.com",
        "sites.google.com",
        "docs.google.com",
        "forms.gle",
        "forms.google.com",
        "drive.google.com",
        "googleusercontent.com",
        "youtube.com",
        "youtu.be",
        "twitter.com",
        "x.com",
        "tiktok.com",
        "telegram.org",
        "t.me",
        "telegram.me",
        "zalo.me",
        "github.com",
        "github.io",
        "gitlab.io",
        "notion.site",
        "canva.com",
        "canva.site",
        "linktr.ee",
        "medium.com",
        "wordpress.com",
        "blogspot.com",
        "wixsite.com",
        "weebly.com",
        "firebaseapp.com",
        "web.app",
        "netlify.app",
        "vercel.app",
        "pages.dev",
        "workers.dev",
        "onrender.com",
        "render.com",
        "herokuapp.com",
        "glitch.me",
        "jimdosite.com",
    })
    return free_hosts


def _get_official_domains() -> set[str]:
    """Return lowercase set of official brand domains from vn_brands.json."""
    kb_path = Path(__file__).resolve().parent.parent / "knowledge_base" / "vn_brands.json"
    official_domains: set[str] = {"gov.vn"}
    if kb_path.exists():
        try:
            with open(kb_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            brands = data if isinstance(data, list) else data.get("brands", [])
            for b in brands:
                for d in b.get("official_domains", []):
                    official_domains.add(d.lower().strip("."))
        except Exception:
            pass
    return official_domains


def _extract_host_and_path(url_or_dom: str) -> tuple[str, str, str]:
    """Extract (host, path, registrable) from a domain or url string."""
    if not url_or_dom:
        return "", "", ""
    cleaned = url_or_dom.lower().strip(" \t\r\n./")
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    if "/" in cleaned:
        h, p = cleaned.split("/", 1)
        p = "/" + p.rstrip("/")
    else:
        h = cleaned
        p = ""

    h = h.split(":")[0].strip(".")
    if not h or "." not in h:
        return "", "", ""

    reg = compute_registrable_domain(h).lower().strip(".")
    return h, p, reg


class PhishBlacklist:
    """
    Exact-match phishing blacklist powered by PhishVN datasets.
    Prevents false positives by strictly excluding:
      (a) platform_domains and all their subdomains (unless exact path matches);
      (b) official_domains of recognized brands (never blacklisted by host);
      (c) conflicted hosts (domains marked benign in the dataset).
    """

    def __init__(
        self,
        hosts: set[str] | None = None,
        registrables: set[str] | None = None,
        platform_paths: set[str] | None = None,
        use_default_samples: bool = True,
        platform_domains: set[str] | None = None,
        official_domains: set[str] | None = None,
        conflicted_hosts: set[str] | None = None,
    ):
        self.platform_domains: set[str] = (
            {p.lower().strip(".") for p in platform_domains if p}
            if platform_domains is not None
            else _get_platform_and_free_hosting()
        )
        self.official_domains: set[str] = (
            {o.lower().strip(".") for o in official_domains if o}
            if official_domains is not None
            else _get_official_domains()
        )
        self.conflicted_hosts: set[str] = (
            {c.lower().strip(".") for c in conflicted_hosts if c}
            if conflicted_hosts is not None
            else set()
        )

        raw_hosts: set[str] = set()
        if hosts is None:
            if use_default_samples:
                raw_hosts.update(DEFAULT_SAMPLE_PHISH_HOSTS)
        else:
            raw_hosts.update(h.lower().strip(".") for h in hosts if h)

        raw_regs: set[str] = {r.lower().strip(".") for r in (registrables or set()) if r}

        # Filter out platform, official, and conflicted domains from hosts and registrables
        self.hosts: set[str] = {
            h for h in raw_hosts
            if not self.is_platform(h) and not self.is_official(h) and not self.is_conflicted(h)
        }
        self.registrables: set[str] = {
            r for r in raw_regs
            if not self.is_platform(r) and not self.is_official(r) and not self.is_conflicted(r)
        }
        self.platform_paths: set[str] = {p.lower() for p in (platform_paths or set()) if p}

    def is_platform(self, host: str, reg: str = "") -> bool:
        """Check if host or its registrable domain belongs to platform_domains or any subdomain."""
        if not host:
            return False
        h = host.lower().strip(".")
        if h in self.platform_domains:
            return True
        if any(h.endswith("." + p) for p in self.platform_domains):
            return True
        if reg and reg in self.platform_domains:
            return True
        return False

    def is_official(self, host: str, reg: str = "") -> bool:
        """Check if host or its registrable domain belongs to official brand domains or any subdomain."""
        if not host:
            return False
        h = host.lower().strip(".")
        if h in self.official_domains:
            return True
        if any(h.endswith("." + o) for o in self.official_domains):
            return True
        if reg and reg in self.official_domains:
            return True
        return False

    def is_conflicted(self, host: str, reg: str = "") -> bool:
        """Check if host or its registrable domain is among conflicted domains (benign in dataset)."""
        if not host:
            return False
        h = host.lower().strip(".")
        if h in self.conflicted_hosts:
            return True
        if reg and reg in self.conflicted_hosts:
            return True
        return False

    @classmethod
    def from_dataset(
        cls,
        data_source: Any = None,
        exclude_splits: list[str] | set[str] | str | None = None,
        use_cache: bool = True,
    ) -> PhishBlacklist:
        """
        Build PhishBlacklist from PhishVN datasets or DatasetLoader.
        Args:
          data_source: None (loads from data/ directory), DatasetLoader instance, or rows.
          exclude_splits: Splits to exclude (e.g. ['test'] or {'test'}) to prevent test leakage.
          use_cache: Whether to use cached instance for file/default data sources.
        """
        exclude_set: set[str] = set()
        if exclude_splits:
            if isinstance(exclude_splits, str):
                exclude_set = {exclude_splits.lower()}
            else:
                exclude_set = {s.lower() for s in exclude_splits}

        platform_domains = _get_platform_and_free_hosting()
        official_domains = _get_official_domains()

        raw_phish_entries: list[tuple[str, str, str]] = []
        benign_hosts: set[str] = set()

        def process_item(item: dict[str, Any] | str):
            if isinstance(item, dict):
                split_val = str(item.get("split", "")).lower()
                if split_val in exclude_set:
                    return
                label = str(item.get("label", "phishing")).lower()
                val = str(item.get("domain") or item.get("url") or "")
                h, p, reg = _extract_host_and_path(val)
                if not h:
                    return
                if label == "benign":
                    benign_hosts.add(h)
                    if reg:
                        benign_hosts.add(reg)
                elif label == "phishing":
                    raw_phish_entries.append((h, p, reg))
            elif isinstance(item, str):
                h, p, reg = _extract_host_and_path(item)
                if h:
                    raw_phish_entries.append((h, p, reg))

        # 1. Custom rows passed directly (list of dicts or DataFrame)
        if data_source is not None and hasattr(data_source, "iterrows"):
            for _, row in data_source.iterrows():
                process_item(dict(row))
        elif isinstance(data_source, (list, tuple, set)):
            for item in data_source:
                process_item(item)
        else:
            # 2. Check DatasetLoader or local data directory
            data_dir = None
            if data_source is not None and hasattr(data_source, "data_dir"):
                data_dir = Path(data_source.data_dir)
            else:
                candidate_dir = Path(__file__).resolve().parent.parent.parent / "data"
                if candidate_dir.exists():
                    data_dir = candidate_dir

            if not data_dir or not data_dir.exists():
                return cls(
                    hosts=DEFAULT_SAMPLE_PHISH_HOSTS,
                    registrables=set(),
                    platform_paths=set(),
                    platform_domains=platform_domains,
                    official_domains=official_domains,
                    conflicted_hosts=set(),
                )

            cache_key = (str(data_dir.resolve()), tuple(sorted(exclude_set)))
            if use_cache:
                with _cache_lock:
                    if cache_key in _dataset_blacklist_cache:
                        return _dataset_blacklist_cache[cache_key]

            # 3. Read splits if available
            splits_dir = data_dir / "data-phising-VN-ver2" / "splits"
            if splits_dir.exists():
                split_files = [
                    ("train", splits_dir / "url_train.csv"),
                    ("val", splits_dir / "url_val.csv"),
                    ("test", splits_dir / "url_test.csv"),
                ]
                for s_name, s_file in split_files:
                    if s_name in exclude_set or not s_file.exists():
                        continue
                    try:
                        with open(s_file, "r", encoding="utf-8", errors="ignore") as f:
                            reader = csv.DictReader(f)
                            for row in reader:
                                val = row.get("domain") or row.get("url") or ""
                                label = (row.get("label") or "").strip().lower()
                                h, p, reg = _extract_host_and_path(val)
                                if not h:
                                    continue
                                if label == "benign":
                                    benign_hosts.add(h)
                                    if reg:
                                        benign_hosts.add(reg)
                                elif label == "phishing":
                                    raw_phish_entries.append((h, p, reg))
                    except Exception:
                        pass
            else:
                # Fallback to dataset_url.csv in target dirs
                target_dirs = [
                    data_dir / "data-phising-VN-ver1",
                    data_dir / "data-phising-VN-ver2",
                ]
                for tdir in target_dirs:
                    csv_path = tdir / "dataset_url.csv"
                    if csv_path.exists():
                        try:
                            with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                                reader = csv.DictReader(f)
                                for row in reader:
                                    val = row.get("domain") or row.get("url") or ""
                                    label = (row.get("label") or "").strip().lower()
                                    h, p, reg = _extract_host_and_path(val)
                                    if not h:
                                        continue
                                    if label == "benign":
                                        benign_hosts.add(h)
                                        if reg:
                                            benign_hosts.add(reg)
                                    elif label == "phishing":
                                        raw_phish_entries.append((h, p, reg))
                        except Exception:
                            pass

        # Calculate conflicted hosts (appeared in phishing AND in benign)
        conflicted_hosts: set[str] = set()
        for h, _, reg in raw_phish_entries:
            if h in benign_hosts:
                conflicted_hosts.add(h)
            if reg and reg in benign_hosts:
                conflicted_hosts.add(reg)

        hosts: set[str] = set(DEFAULT_SAMPLE_PHISH_HOSTS)
        registrables: set[str] = set()
        platform_paths: set[str] = set()

        def _is_plat(host_val: str, reg_val: str = "") -> bool:
            if not host_val:
                return False
            if host_val in platform_domains or any(host_val.endswith("." + p) for p in platform_domains):
                return True
            if reg_val and reg_val in platform_domains:
                return True
            return False

        def _is_off(host_val: str, reg_val: str = "") -> bool:
            if not host_val:
                return False
            if host_val in official_domains or any(host_val.endswith("." + o) for o in official_domains):
                return True
            if reg_val and reg_val in official_domains:
                return True
            return False

        for h, p, reg in raw_phish_entries:
            if _is_plat(h, reg):
                # NEVER add platform domain to hosts or registrables
                # Only add exact path if present
                if p and p != "/":
                    platform_paths.add(f"{h}{p}".lower())
                    if reg and reg != h:
                        platform_paths.add(f"{reg}{p}".lower())
                    if h.startswith("www."):
                        platform_paths.add(f"{h[4:]}{p}".lower())
                continue

            if _is_off(h, reg):
                # NEVER add official brand domain to hosts or registrables
                continue

            if h in conflicted_hosts or h in benign_hosts:
                pass
            else:
                hosts.add(h)

            if reg:
                if reg in conflicted_hosts or reg in benign_hosts:
                    pass
                else:
                    registrables.add(reg)

        instance = cls(
            hosts=hosts,
            registrables=registrables,
            platform_paths=platform_paths,
            use_default_samples=True,
            platform_domains=platform_domains,
            official_domains=official_domains,
            conflicted_hosts=conflicted_hosts,
        )

        if data_source is None and use_cache and 'cache_key' in locals():
            with _cache_lock:
                _dataset_blacklist_cache[cache_key] = instance

        return instance

    def lookup(self, parsed: ParsedUrl | str) -> dict[str, Any]:
        """
        Check if parsed URL hits the phishing blacklist.
        Returns: {hit: bool, level: 'host' | 'registrable' | 'path' | None, source: str}
        """
        if isinstance(parsed, str):
            from codebase.url_analysis.parse import parse_url
            parsed = parse_url(parsed)

        host = (parsed.effective_host or "").lower().strip(".")
        reg = (parsed.registrable_domain or "").lower().strip(".")
        path = parsed.path or ""
        norm_path = path.rstrip("/") if len(path) > 1 else path

        # 1. Platform domain: NEVER hit by host/registrable.
        # Only hit if full URL has an exact path match in platform_paths.
        if self.is_platform(host, reg):
            if host and path and path != "/":
                keys_to_check = [f"{host}{path}".lower(), f"{host}{norm_path}".lower()]
                if reg and reg != host:
                    keys_to_check.extend([f"{reg}{path}".lower(), f"{reg}{norm_path}".lower()])
                if host.startswith("www."):
                    keys_to_check.extend([f"{host[4:]}{path}".lower(), f"{host[4:]}{norm_path}".lower()])
                for k in keys_to_check:
                    if k in self.platform_paths:
                        return {"hit": True, "level": "path", "source": "PhishVN"}
            return {"hit": False, "level": None, "source": ""}

        # 2. Official brand domain: NEVER hit by host/registrable.
        if self.is_official(host, reg):
            return {"hit": False, "level": None, "source": ""}

        # 3. Conflicted host (appeared as benign in dataset): NEVER hit.
        if self.is_conflicted(host, reg):
            return {"hit": False, "level": None, "source": ""}

        # 4. Exact host match
        if host and host in self.hosts:
            return {"hit": True, "level": "host", "source": "PhishVN"}

        # 5. Exact registrable domain match
        if reg and reg in self.registrables:
            return {"hit": True, "level": "registrable", "source": "PhishVN"}

        # 6. Fallback path match
        if host and path and path != "/":
            if f"{host}{path}".lower() in self.platform_paths or f"{host}{norm_path}".lower() in self.platform_paths:
                return {"hit": True, "level": "path", "source": "PhishVN"}

        return {"hit": False, "level": None, "source": ""}
