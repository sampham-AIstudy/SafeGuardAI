import os
import sys
import json
import re

from pathlib import Path

# Add root project dir to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from codebase.knowledge_base.dataset_loader import DatasetLoader
from codebase.knowledge_base.db_connect import MySQLManager
from codebase.text_utils import PhraseMatcher

DEFAULT_KB_PATH = Path(__file__).resolve().parent.parent / "knowledge_base" / "vn_scam_tactics.json"


class RAGAgent:
    """
    RAG Agent:
    Searches Vietnamese Scam Knowledge Base, MySQL Database `ai-anti-scam` (phishing_urls),
    PhishVN Datasets (ver1 & ver2 - 51,362 records), and Global Email/SMS Phishing Datasets.
    Matches query text and extracted URLs/domains against hybrid local & MySQL threat feeds.
    """
    def __init__(self, kb_path=None):
        self.kb_path = Path(kb_path) if kb_path else DEFAULT_KB_PATH
        self._matchers = {}
        self.tactics = self._load_kb()
        self.loader = DatasetLoader()
        self.phish_data = self.loader.load_phish_vn_datasets()
        self.global_data = self.loader.load_global_phishing_datasets()
        self.db_manager = MySQLManager()

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

    def search(self, query_text):
        matched_tactics = []
        matched_flags = []
        matched_phish_domains = []
        query_text = query_text or ""
        query_lower = query_text.lower()

        # 1. Match Scam Tactics Knowledge Base (VN Scams) using PhraseMatcher
        for idx, tactic in enumerate(self.tactics):
            tid = tactic.get("id") or str(idx)
            matcher = self._matchers.get(tid)
            if matcher:
                hits = matcher.findall(query_text)
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

        # 2. Query MySQL Database `ai-anti-scam` if connected
        if self.db_manager.is_connected and self.db_manager.conn:
            try:
                with self.db_manager.conn.cursor() as cursor:
                    # Extract potential domain tokens from query
                    tokens = [t for t in re.split(r'[\s/:]+', query_lower) if '.' in t and len(t) > 4]
                    for token in tokens:
                        sql = "SELECT `domain`, `scenario` FROM `phishing_urls` WHERE `domain` = %s OR `url` LIKE %s LIMIT 1"
                        cursor.execute(sql, (token, f"%{token}%"))
                        row = cursor.fetchone()
                        if row:
                            dname = row["domain"]
                            if dname not in matched_phish_domains:
                                matched_phish_domains.append(dname)
                                flag_str = f"Tên miền lừa đảo MySQL `ai-anti-scam` (NCSC/ChongLuaDao): {dname} [{row['scenario']}]"
                                if flag_str not in matched_flags:
                                    matched_flags.append(flag_str)
            except Exception as e:
                print(f"[RAGAgent] MySQL search error: {e}")

        # 3. Fallback / Complement with In-memory PhishVN Blacklist Domains
        phish_domains = self.phish_data.get("phishing_domains", set())
        # Optimization: Only run substring match when query contains '.'
        if "." in query_lower:
            for domain in phish_domains:
                if domain and len(domain) > 4 and domain in query_lower:
                    if domain not in matched_phish_domains:
                        matched_phish_domains.append(domain)
                        flag_str = f"Tên miền lừa đảo NCSC/ChongLuaDao: {domain}"
                        if flag_str not in matched_flags:
                            matched_flags.append(flag_str)


        # 4. Match Global Phishing Patterns (English / Global Email & SMS Spam)
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
    print(f"[RAGAgent] MySQL Active: {res['mysql_active']}")
    print("Matched flags:", res["matched_flags"])
