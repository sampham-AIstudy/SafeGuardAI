import os
import json
from pathlib import Path
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DATA_DIR = ROOT_DIR / "data"
DEFAULT_KB_PATH = Path(__file__).resolve().parent / "vn_scam_tactics.json"


import threading

_cache_lock = threading.Lock()
_phish_vn_cache = {}
_global_phishing_cache = {}


class DatasetLoader:
    """
    Unified Loader Module for:
    1. Vietnamese PhishVN Datasets (data-phising-VN-ver1 & ver2 - 51,362 records)
    2. Global Phishing Email & SMS Spam Datasets (CEAS, Enron, Nazario, Nigerian Fraud, SpamAssassin, SMS Spam)
    3. Custom Vietnamese Scam Knowledge Base Tactics (vn_scam_tactics.json)
    """
    def __init__(self, data_dir=None):
        self.data_dir = str(data_dir) if data_dir is not None else str(DEFAULT_DATA_DIR)
        self.kb_path = str(DEFAULT_KB_PATH)
        if not os.path.exists(self.data_dir):
            print(f"[DatasetLoader] [WARNING] Data directory '{self.data_dir}' not found. Threat feeds will operate in offline fallback mode without local CSV datasets.")


    def load_knowledge_base(self):
        if os.path.exists(self.kb_path):
            with open(self.kb_path, "r", encoding="utf-8") as f:
                return json.load(f).get("scam_tactics", [])
        return []

    def load_phish_vn_datasets(self):
        """
        Loads PhishVN datasets (ver1 & ver2) containing 50,000+ localized VN phishing URLs.
        Thread-safe module-level cache keyed by self.data_dir.
        """
        with _cache_lock:
            if self.data_dir in _phish_vn_cache:
                cached = _phish_vn_cache[self.data_dir]
                return {
                    "total_phishing_records": cached["total_phishing_records"],
                    "phishing_domains": cached["phishing_domains"],
                    "phishing_urls": cached["phishing_urls"],
                    "scenarios": cached["scenarios"]
                }

        phishing_domains = set()
        phishing_urls = set()
        scenario_counts = {}
        total_records = 0

        target_dirs = [
            os.path.join(self.data_dir, "data-phising-VN-ver1"),
            os.path.join(self.data_dir, "data-phising-VN-ver2")
        ]

        for tdir in target_dirs:
            csv_path = os.path.join(tdir, "dataset_url.csv")
            if os.path.exists(csv_path):
                try:
                    df = pd.read_csv(csv_path, low_memory=False)
                    phish_df = df[df["label"] == "phishing"]
                    total_records += len(phish_df)

                    for _, row in phish_df.iterrows():
                        domain = str(row.get("domain", "")).strip().lower()
                        url = str(row.get("url", "")).strip().lower()
                        scenario = str(row.get("scenario", "other")).strip().lower()

                        if domain and domain != "nan":
                            phishing_domains.add(domain)
                        if url and url != "nan":
                            phishing_urls.add(url)

                        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1
                except Exception as e:
                    print(f"[DatasetLoader] Error loading {csv_path}: {e}")

        result = {
            "total_phishing_records": total_records,
            "phishing_domains": phishing_domains,
            "phishing_urls": phishing_urls,
            "scenarios": scenario_counts
        }
        with _cache_lock:
            _phish_vn_cache[self.data_dir] = result
        return {
            "total_phishing_records": result["total_phishing_records"],
            "phishing_domains": result["phishing_domains"],
            "phishing_urls": result["phishing_urls"],
            "scenarios": result["scenarios"]
        }

    def load_global_phishing_datasets(self):
        """
        Loads international datasets (CEAS, Enron, Nazario, Nigerian Fraud, SpamAssassin, SMS Spam).
        Extracts global keywords & spam patterns.
        Thread-safe module-level cache keyed by self.data_dir.
        """
        with _cache_lock:
            if self.data_dir in _global_phishing_cache:
                return dict(_global_phishing_cache[self.data_dir])

        global_dir = os.path.join(self.data_dir, "phising-email-dataset")
        global_keywords = set()
        total_global_files = 0

        if os.path.exists(global_dir):
            for fname in os.listdir(global_dir):
                if fname.endswith(".csv"):
                    total_global_files += 1
                    try:
                        fpath = os.path.join(global_dir, fname)
                        df = pd.read_csv(fpath, nrows=500, encoding="utf-8", on_bad_lines="skip")
                        for text_col in df.columns:
                            if any(c in text_col.lower() for c in ["text", "email", "body", "message", "subject"]):
                                sample_texts = df[text_col].dropna().astype(str).str.lower()
                                for t in sample_texts:
                                    if any(k in t for k in ["urgent", "wire transfer", "lottery", "account locked", "verify now", "click here", "bank", "security"]):
                                        global_keywords.add("global_phishing_pattern")
                    except Exception:
                        pass

        result = {
            "total_global_files": total_global_files,
            "has_global_datasets": total_global_files > 0,
            "global_patterns_loaded": len(global_keywords)
        }
        with _cache_lock:
            _global_phishing_cache[self.data_dir] = result
        return dict(result)

if __name__ == "__main__":
    loader = DatasetLoader()
    kb = loader.load_knowledge_base()
    phish_vn = loader.load_phish_vn_datasets()
    global_data = loader.load_global_phishing_datasets()
    print(f"[DatasetLoader] VN Tactics: {len(kb)} | PhishVN Records: {phish_vn['total_phishing_records']} | Global CSV Files: {global_data['total_global_files']}")
