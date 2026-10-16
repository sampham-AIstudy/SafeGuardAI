from __future__ import annotations

import csv
import json
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


def _get_platform_and_free_hosting() -> set[str]:
    """Return lowercase set of free hosting and platform domains to exclude from registrable blacklist."""
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

    # Ensure core platforms are present
    free_hosts.update({
        "facebook.com",
        "sites.google.com",
        "docs.google.com",
        "forms.gle",
        "drive.google.com",
        "github.io",
        "gitlab.io",
        "weebly.com",
        "wixsite.com",
        "blogspot.com",
        "wordpress.com",
        "canva.site",
        "vercel.app",
        "web.app",
        "firebaseapp.com",
        "telegram.me",
        "t.me",
    })
    return free_hosts


class PhishBlacklist:
    """
    Exact-match phishing blacklist powered by PhishVN datasets.
    Prevents false positives by strictly excluding major platform/free hosting
    domains from the registrable blacklist level.
    """

    def __init__(
        self,
        hosts: set[str] | None = None,
        registrables: set[str] | None = None,
        platform_paths: set[str] | None = None,
        use_default_samples: bool = True,
    ):
        if hosts is None:
            self.hosts: set[str] = set(DEFAULT_SAMPLE_PHISH_HOSTS) if use_default_samples else set()
        else:
            self.hosts = {h.lower().strip(".") for h in hosts if h}

        self.registrables: set[str] = {r.lower().strip(".") for r in (registrables or set()) if r}
        self.platform_paths: set[str] = {p.lower() for p in (platform_paths or set()) if p}
        self.platform_domains = _get_platform_and_free_hosting()

    @classmethod
    def from_dataset(
        cls,
        data_source: Any = None,
        exclude_splits: list[str] | set[str] | str | None = None,
    ) -> PhishBlacklist:
        """
        Build PhishBlacklist from PhishVN datasets or DatasetLoader.
        Args:
          data_source: None (loads from data/ directory), DatasetLoader instance, or rows.
          exclude_splits: Splits to exclude (e.g. ['test'] or {'test'}) to prevent test leakage.
        """
        exclude_set: set[str] = set()
        if exclude_splits:
            if isinstance(exclude_splits, str):
                exclude_set = {exclude_splits.lower()}
            else:
                exclude_set = {s.lower() for s in exclude_splits}

        hosts: set[str] = set(DEFAULT_SAMPLE_PHISH_HOSTS)
        registrables: set[str] = set()
        platform_paths: set[str] = set()
        platform_domains = _get_platform_and_free_hosting()

        def add_entry(url_or_dom: str, path_val: str = ""):
            if not url_or_dom:
                return
            cleaned = url_or_dom.lower().strip(" \t\r\n./")
            if "://" in cleaned:
                cleaned = cleaned.split("://", 1)[1]
            if "/" in cleaned:
                h, p = cleaned.split("/", 1)
                p = "/" + p
            else:
                h = cleaned
                p = path_val

            h = h.split(":")[0].strip(".")
            if not h or "." not in h:
                return

            reg = compute_registrable_domain(h).lower().strip(".")

            # Check if domain belongs to a major platform or free hosting provider
            is_platform = (
                h in platform_domains
                or reg in platform_domains
                or any(h.endswith("." + plat) for plat in platform_domains)
            )

            if is_platform:
                # NEVER add platform domain to registrables
                # Only add specific host (if not bare platform) and path if present
                if h not in platform_domains:
                    hosts.add(h)
                if p and p != "/":
                    platform_paths.add(f"{h}{p}")
            else:
                hosts.add(h)
                if reg:
                    registrables.add(reg)

        # 1. Custom rows passed directly (list of dicts or DataFrame)
        if data_source is not None and hasattr(data_source, "iterrows"):
            for _, row in data_source.iterrows():
                if row.get("label") == "phishing":
                    split_val = str(row.get("split", "")).lower()
                    if split_val in exclude_set:
                        continue
                    add_entry(str(row.get("domain") or row.get("url") or ""))
            return cls(hosts=hosts, registrables=registrables, platform_paths=platform_paths)

        if isinstance(data_source, (list, tuple, set)):
            for item in data_source:
                if isinstance(item, dict):
                    if item.get("label", "phishing") == "phishing":
                        split_val = str(item.get("split", "")).lower()
                        if split_val in exclude_set:
                            continue
                        add_entry(str(item.get("domain") or item.get("url") or ""))
                elif isinstance(item, str):
                    add_entry(item)
            return cls(hosts=hosts, registrables=registrables, platform_paths=platform_paths)

        # 2. Check DatasetLoader or local data directory
        data_dir = None
        if data_source is not None and hasattr(data_source, "data_dir"):
            data_dir = Path(data_source.data_dir)
        else:
            # Look for project data directory
            candidate_dir = Path(__file__).resolve().parent.parent.parent / "data"
            if candidate_dir.exists():
                data_dir = candidate_dir

        if not data_dir or not data_dir.exists():
            # Graceful offline fallback without local datasets
            return cls(hosts=hosts, registrables=registrables, platform_paths=platform_paths)

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
                            if row.get("label") == "phishing":
                                add_entry(row.get("domain") or row.get("url") or "")
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
                                if row.get("label") == "phishing":
                                    add_entry(row.get("domain") or row.get("url") or "")
                    except Exception:
                        pass

        return cls(hosts=hosts, registrables=registrables, platform_paths=platform_paths)

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

        # 1. Exact host match
        if host and host in self.hosts:
            return {"hit": True, "level": "host", "source": "PhishVN"}

        # 2. Exact registrable domain match
        if reg and reg in self.registrables:
            return {"hit": True, "level": "registrable", "source": "PhishVN"}

        # 3. Platform path match
        if host and path:
            key = f"{host}{path}".lower()
            if key in self.platform_paths:
                return {"hit": True, "level": "path", "source": "PhishVN"}

        return {"hit": False, "level": None, "source": ""}
