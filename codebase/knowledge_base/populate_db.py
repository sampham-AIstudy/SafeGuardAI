import os
import sys
import json
import pandas as pd

# Add root project dir to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from codebase.knowledge_base.db_connect import MySQLManager

def populate_database():
    """
    Populates PhishVN dataset (50,000+ records) and VN Scam Tactics
    into XAMPP MySQL database `ai-anti-scam`.
    """
    db = MySQLManager()
    if not db.is_connected or not db.conn:
        print("[PopulateDB] Error: Cannot connect to MySQL XAMPP database `ai-anti-scam`.")
        print("[PopulateDB] Please ensure XAMPP MySQL is running on localhost:3306.")
        return

    conn = db.conn

    # 1. Populate Scam Tactics from JSON
    kb_path = os.path.join("codebase", "knowledge_base", "vn_scam_tactics.json")
    if os.path.exists(kb_path):
        with open(kb_path, "r", encoding="utf-8") as f:
            tactics = json.load(f).get("scam_tactics", [])

        print(f"[PopulateDB] Populating {len(tactics)} scam tactics into `scam_tactics` table...")
        with conn.cursor() as cursor:
            for t in tactics:
                flags_str = ", ".join(t.get("red_flags", []))
                sql = """
                INSERT INTO `scam_tactics` (`id`, `category`, `title`, `red_flags`)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE `title` = VALUES(`title`), `red_flags` = VALUES(`red_flags`);
                """
                cursor.execute(sql, (t["id"], t["category"], t["title"], flags_str))
        conn.commit()
        print("✅ `scam_tactics` table updated.")

    # 2. Populate PhishVN Dataset into `phishing_urls` table
    data_dirs = [
        os.path.join("data", "data-phising-VN-ver1", "dataset_url.csv"),
        os.path.join("data", "data-phising-VN-ver2", "dataset_url.csv")
    ]

    total_inserted = 0

    for csv_file in data_dirs:
        if os.path.exists(csv_file):
            print(f"[PopulateDB] Reading CSV: {csv_file}...")
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                phish_df = df[df["label"] == "phishing"]
                print(f"[PopulateDB] Found {len(phish_df)} phishing records in {csv_file}.")

                batch_data = []
                for _, row in phish_df.iterrows():
                    url = str(row.get("url", "")).strip()[:767]
                    domain = str(row.get("domain", "")).strip()[:255]
                    scenario = str(row.get("scenario", "other")).strip()[:50]
                    source = str(row.get("source", "PhishVN")).strip()[:100]

                    if url and domain and domain != "nan":
                        batch_data.append((url, domain, scenario, source))

                # Batch insert into MySQL
                if batch_data:
                    batch_size = 1000
                    with conn.cursor() as cursor:
                        sql = """
                        INSERT IGNORE INTO `phishing_urls` (`url`, `domain`, `scenario`, `source`)
                        VALUES (%s, %s, %s, %s)
                        """
                        for i in range(0, len(batch_data), batch_size):
                            chunk = batch_data[i:i + batch_size]
                            cursor.executemany(sql, chunk)
                            conn.commit()
                            total_inserted += len(chunk)
                            print(f"  Inserted {min(i + batch_size, len(batch_data))}/{len(batch_data)} records...")

            except Exception as e:
                print(f"[PopulateDB] Error loading {csv_file}: {e}")

    print("=" * 70)
    print(f"🎉 POPULATE SUCCESSFUL: Total {total_inserted} Phishing URLs populated into MySQL `ai-anti-scam`!")
    print("=" * 70)

    db.close()

if __name__ == "__main__":
    populate_database()
