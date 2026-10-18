import os
import sys
import json
import re

from pathlib import Path

# Add root project dir to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from codebase.knowledge_base.dataset_loader import DatasetLoader
from codebase.knowledge_base.db_connect import SQLiteManager
from codebase.text_utils import PhraseMatcher
from codebase.config import get_settings
from typing import Any

DEFAULT_KB_PATH = Path(__file__).resolve().parent.parent / "knowledge_base" / "vn_scam_tactics.json"


def _extract_blacklist_domains_from_report(url_report: Any) -> list[str]:
    """
    Extract unique effective_host / registrable domains (preserving order)
    from all findings (including children) in url_report that have a BLACKLIST_HIT signal.
    """
    if not url_report:
        return []

    findings = getattr(url_report, "findings", None)
    if findings is None and isinstance(url_report, dict):
        findings = url_report.get("findings", [])
    if not findings:
        return []

    matched_domains: list[str] = []
    seen: set[str] = set()

    def _traverse(finding):
        if not finding:
            return
        sigs = getattr(finding, "signals", None)
        if sigs is None and isinstance(finding, dict):
            sigs = finding.get("signals", [])

        has_blacklist_hit = False
        hit_level = ""
        for s in (sigs or []):
            code = getattr(s, "code", None) if not isinstance(s, dict) else s.get("code")
            if code == "BLACKLIST_HIT":
                has_blacklist_hit = True
                ev = getattr(s, "evidence", "") if not isinstance(s, dict) else s.get("evidence", "")
                if "level=registrable" in str(ev):
                    hit_level = "registrable"
                elif "level=host" in str(ev):
                    hit_level = "host"
                break

        if has_blacklist_hit:
            h = getattr(finding, "effective_host", None) if not isinstance(finding, dict) else finding.get("effective_host")
            reg = getattr(finding, "registrable_domain", None) if not isinstance(finding, dict) else (finding.get("registrable_domain") or finding.get("registrable"))
            dom = None
            if hit_level == "registrable" and reg:
                dom = reg
            elif hit_level == "host" and h:
                dom = h
            else:
                dom = h or reg

            if dom and isinstance(dom, str):
                cleaned = dom.strip().lower()
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    matched_domains.append(cleaned)

        children = getattr(finding, "children", None)
        if children is None and isinstance(finding, dict):
            children = finding.get("children", [])
        for ch in (children or []):
            _traverse(ch)

    for f in findings:
        _traverse(f)

    return matched_domains


class RAGAgent:
    """
    RAG Agent:
    Searches Vietnamese Scam Knowledge Base, PhishVN Datasets (ver1 & ver2 - 51,362 records),
    and Global Email/SMS Phishing Datasets.
    Matches query text and extracted URLs/domains against local threat feeds and offline knowledge bases.
    """
    def __init__(self, kb_path=None):
        self.kb_path = Path(kb_path) if kb_path else DEFAULT_KB_PATH
        self._matchers = {}
        self.tactics = self._load_kb()
        self.loader = DatasetLoader()
        self.phish_data = self.loader.load_phish_vn_datasets()
        self.global_data = self.loader.load_global_phishing_datasets()
        self.db_manager = SQLiteManager()
        self._url_analyzer = None
        self._cached_phish_id = None
        self._custom_analyzers: dict[int, Any] = {}

    def _get_url_analyzer(self):
        try:
            from codebase.url_analysis import get_shared_url_analyzer
            shared = get_shared_url_analyzer()
        except Exception:
            return None

        # Check if self.phish_data matches the dataset used by shared analyzer
        phish_id = id(self.phish_data)
        is_same = False

        if hasattr(shared, "_source_data_id") and shared._source_data_id is not None:
            if phish_id == shared._source_data_id:
                is_same = True

        if not is_same and hasattr(shared, "_source_domains_hash") and shared._source_domains_hash is not None:
            try:
                curr_domains = self.phish_data.get("phishing_domains", set()) if isinstance(self.phish_data, dict) else set()
                if hash(frozenset(curr_domains)) == shared._source_domains_hash:
                    is_same = True
            except Exception:
                pass

        if is_same:
            return shared

        # Different: build isolated PhishBlacklist using the same full-layer factory
        # (excluding platforms/officials/conflicted), cached by id(phish_data)
        if phish_id in self._custom_analyzers:
            return self._custom_analyzers[phish_id]

        try:
            from codebase.url_analysis.blacklist import PhishBlacklist
            from codebase.url_analysis.analyzer import UrlAnalyzer

            raw_items = []
            if isinstance(self.phish_data, dict):
                raw_items.extend(self.phish_data.get("phishing_domains", []))
                raw_items.extend(self.phish_data.get("phishing_urls", []))
            elif isinstance(self.phish_data, (list, tuple, set)):
                raw_items.extend(self.phish_data)

            custom_bl = PhishBlacklist.from_dataset(raw_items, use_cache=False)
            custom_analyzer = UrlAnalyzer(blacklist=custom_bl)
            self._custom_analyzers[phish_id] = custom_analyzer
            return custom_analyzer
        except Exception:
            return shared

    def _load_kb(self):
        if os.path.exists(self.kb_path):
            with open(self.kb_path, "r", encoding="utf-8") as f:
                tactics = json.load(f).get("scam_tactics", [])
                for idx, tactic in enumerate(tactics):
                    tid = tactic.get("id") or str(idx)
                    phrases = tactic.get("trigger_phrases") or tactic.get("red_flags", [])
                    self._matchers[tid] = PhraseMatcher(phrases)
                return tactics
        return []

    def search(self, query_text: str = "", url_report: Any = None):
        matched_tactics = []
        matched_flags = []
        matched_phish_domains = []
        query_text = query_text or ""
        query_lower = query_text.lower()

        # Protect tactic PhraseMatchers against repetitive adversarial strings
        if len(query_text) > 1000 and len(set(query_text[:500])) <= 4:
            tactic_search_text = query_text[:1000]
        else:
            tactic_search_text = query_text

        # 1. Match Scam Tactics Knowledge Base (VN Scams) using PhraseMatcher
        for idx, tactic in enumerate(self.tactics):
            tid = tactic.get("id") or str(idx)
            matcher = self._matchers.get(tid)
            if matcher:
                hits = matcher.findall(tactic_search_text)
            else:
                hits = [flag for flag in tactic.get("red_flags", []) if flag.lower() in query_lower]
            tactic_hits = len(hits)
            if tactic_hits > 0:
                for hit in hits:
                    if hit not in matched_flags:
                        matched_flags.append(hit)
                denom = len(tactic.get("trigger_phrases", [])) or len(tactic.get("red_flags", [])) or 1
                matched_tactics.append({
                    "tactic": tactic,
                    "matched_count": tactic_hits,
                    "score": round(tactic_hits / denom, 2)
                })

        # Sort by matched score descending
        matched_tactics.sort(key=lambda x: x["matched_count"], reverse=True)

        # 2. PhishVN Blacklist Domains
        phish_domains = self.phish_data.get("phishing_domains", set())

        if get_settings().url_module_enabled:
            # Module enabled: Do NOT run 36.8k substring scan
            analyzer = self._get_url_analyzer()
            if url_report is not None:
                new_matched = _extract_blacklist_domains_from_report(url_report)
                for d in new_matched:
                    if d not in matched_phish_domains:
                        matched_phish_domains.append(d)
                        flag_str = f"Tên miền lừa đảo NCSC/ChongLuaDao: {d}"
                        if flag_str not in matched_flags:
                            matched_flags.append(flag_str)
                # If custom analyzer is used (different dataset), complement with matches from custom analyzer
                if "." in query_text and analyzer is not None:
                    try:
                        from codebase.url_analysis import get_shared_url_analyzer
                        if analyzer is not get_shared_url_analyzer():
                            rep_custom = analyzer.analyze_text(query_text)
                            for d in _extract_blacklist_domains_from_report(rep_custom):
                                if d not in matched_phish_domains:
                                    matched_phish_domains.append(d)
                                    flag_str = f"Tên miền lừa đảo NCSC/ChongLuaDao: {d}"
                                    if flag_str not in matched_flags:
                                        matched_flags.append(flag_str)
                    except Exception:
                        pass
            else:
                # url_report is None: lazy analysis with UrlAnalyzer if query contains potential domain/URL
                if "." in query_text:
                    if analyzer:
                        try:
                            rep = analyzer.analyze_text(query_text)
                            new_matched = _extract_blacklist_domains_from_report(rep)
                            for d in new_matched:
                                if d not in matched_phish_domains:
                                    matched_phish_domains.append(d)
                                    flag_str = f"Tên miền lừa đảo NCSC/ChongLuaDao: {d}"
                                    if flag_str not in matched_flags:
                                        matched_flags.append(flag_str)
                        except Exception:
                            pass
        else:
            # Module disabled: keep exact legacy substring match when query contains '.'
            if "." in query_lower:
                for domain in phish_domains:
                    if domain and len(domain) > 4 and domain in query_lower:
                        if domain not in matched_phish_domains:
                            matched_phish_domains.append(domain)
                            flag_str = f"Tên miền lừa đảo NCSC/ChongLuaDao: {domain}"
                            if flag_str not in matched_flags:
                                matched_flags.append(flag_str)


        # 3. Match Global Phishing Patterns (English / Global Email & SMS Spam)
        global_indicators = ["wire transfer", "verify account now", "lottery winner", "nigerian prince", "account locked"]
        for ind in global_indicators:
            if ind in query_lower:
                flag_str = f"Global Phishing Threat Indicator: {ind}"
                if flag_str not in matched_flags:
                    matched_flags.append(flag_str)

        return {
            "matched_tactics": matched_tactics,
            "matched_flags": matched_flags,
            "matched_phish_domains": matched_phish_domains,
            "db_active": self.db_manager.is_connected,
            "mysql_active": self.db_manager.is_connected,
            "phish_vn_stats": {
                "total_phishing_records": self.phish_data.get("total_phishing_records", 0),
                "unique_domains": len(phish_domains)
            },
            "global_stats": {
                "total_files": self.global_data.get("total_global_files", 0)
            },
            "total_patterns_matched": len(matched_flags)
        }

if __name__ == "__main__":
    rag = RAGAgent()
    res = rag.search("Truy cập ngay chinhphu2025.com hoặc dvc.bcavn.cc để nạp quỹ tuyển dụng tiktok")
    print(f"[RAGAgent] Matched {len(res['matched_tactics'])} tactics, {len(res['matched_phish_domains'])} PhishVN domains.")
    print(f"[RAGAgent] DB Active: {res['db_active']}")
    print("Matched flags:", res["matched_flags"])
