import argparse
import base64
import csv
import idna
import json
import os
import random
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from codebase.agents.explainable_agent import ExplainableAgent

CYRILLIC_HOMOGLYPHS: dict[str, str] = {
    "a": "\u0430",
    "e": "\u0435",
    "o": "\u043e",
    "p": "\u0440",
    "c": "\u0441",
    "x": "\u0445",
    "i": "\u0456",
}

TECHNIQUE_SIGNALS: dict[str, set[str]] = {
    "defang": {"DEFANGED"},
    "percent_host": {"ENCODED_HOST"},
    "zero_width": {"ZERO_WIDTH"},
    "fullwidth": {"FULLWIDTH_OR_ODD_DOT"},
    "userinfo_decoy": {"USERINFO_PRESENT", "USERINFO_BRAND_DECOY", "USERINFO_CONFUSION"},
    "open_redirect": {"OPEN_REDIRECT_TRUSTED", "EMBEDDED_URL"},
    "base64_param": {"BASE64_URL", "EMBEDDED_URL"},
    "shortener": {"SHORTENER"},
    "homoglyph_cyrillic": {"HOMOGLYPH_BRAND", "MIXED_SCRIPT", "PUNYCODE_HOST"},
    "punycode_idn": {"PUNYCODE_HOST", "MIXED_SCRIPT", "HOMOGLYPH_BRAND"},
    "ip_decimal": {"IP_OBFUSCATED", "IP_HOST"},
    "backslash_confusion": {"BACKSLASH_CONFUSION"},
    "nested_redirect": {"OPEN_REDIRECT_TRUSTED", "EMBEDDED_URL"},
    "double_encoding": {"DOUBLE_ENCODING"},
    "hex_param": {"HEX_URL", "EMBEDDED_URL"},
}


def to_fullwidth(s: str) -> str:
    """Convert ASCII characters to Unicode fullwidth counterparts."""
    res = []
    for c in s:
        code = ord(c)
        if 0x21 <= code <= 0x7E:
            res.append(chr(code + 0xFEE0))
        else:
            res.append(c)
    return "".join(res)


def extract_host(url: str) -> str:
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    try:
        return urlparse(u).netloc.split(":")[0].lower()
    except Exception:
        return u.split("/")[0].lower()


# ─────────────────────────────────────────────────────────────────────────────
# AUGMENTATION TRANSFORMS (deterministic with seed 42)
# ─────────────────────────────────────────────────────────────────────────────
def apply_phishing_transform(url: str, transform: str, idx: int = 0) -> str:
    u = url.strip()
    norm = u if u.startswith(("http://", "https://")) else f"http://{u}"
    host = extract_host(norm)

    if transform == "identity":
        return norm
    elif transform == "bare_domain":
        return host
    elif transform == "defang":
        return norm.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    elif transform == "percent_host":
        if len(host) >= 3:
            encoded_prefix = "".join(f"%{ord(c):02X}" for c in host[:3])
            return norm.replace(host, encoded_prefix + host[3:], 1)
        return norm
    elif transform == "zero_width":
        if len(host) >= 4:
            mid = len(host) // 2
            zw_host = host[:mid] + "\u200b" + host[mid:]
            return norm.replace(host, zw_host, 1)
        return norm
    elif transform == "fullwidth":
        return to_fullwidth(norm)
    elif transform == "userinfo_decoy":
        return f"https://vietcombank.com.vn@{host}/login"
    elif transform == "open_redirect":
        return f"https://www.google.com/url?q={norm}"
    elif transform == "base64_param":
        b64 = base64.urlsafe_b64encode(norm.encode("utf-8")).decode("ascii").rstrip("=")
        return f"https://track.mail-vn.com/c?u={b64}"
    elif transform == "shortener":
        return f"https://bit.ly/mock_{idx:05d}"
    elif transform == "trailing_punct":
        return f"{norm})."
    elif transform == "homoglyph_cyrillic":
        labels = host.split(".")
        lbl = labels[0]
        new_lbl = "".join(CYRILLIC_HOMOGLYPHS.get(c, c) for c in lbl)
        if new_lbl == lbl:
            for idx_l in range(1, len(labels)):
                cand = "".join(CYRILLIC_HOMOGLYPHS.get(c, c) for c in labels[idx_l])
                if cand != labels[idx_l]:
                    labels[idx_l] = cand
                    break
            else:
                if lbl:
                    labels[0] = "\u0430" + lbl[1:]
        else:
            labels[0] = new_lbl
        new_host = ".".join(labels)
        return norm.replace(host, new_host, 1)
    elif transform == "punycode_idn":
        labels = host.split(".")
        lbl = labels[0]
        homoglyph_lbl = "".join(CYRILLIC_HOMOGLYPHS.get(c, c) for c in lbl)
        if homoglyph_lbl == lbl:
            homoglyph_lbl = "\u0430" + (lbl[1:] if len(lbl) > 1 else "")
        try:
            puny_lbl = idna.encode(homoglyph_lbl).decode("ascii")
        except Exception:
            puny_lbl = f"xn--{lbl}"
        labels[0] = puny_lbl
        new_host = ".".join(labels)
        return norm.replace(host, new_host, 1)
    elif transform == "ip_decimal":
        import ipaddress
        try:
            ip_obj = ipaddress.IPv4Address(host)
            dec_str = str(int(ip_obj))
            return norm.replace(host, dec_str, 1)
        except Exception:
            return norm
    elif transform == "backslash_confusion":
        return f"https://{host}\\@vietcombank.com.vn/"
    elif transform == "nested_redirect":
        enc_q = urllib.parse.quote(norm, safe="")
        return f"https://www.google.com/url?q={enc_q}"
    elif transform == "double_encoding":
        p = urlparse(norm)
        path_part = p.path if p.path and p.path != "/" else "/login"
        double_encoded_path = "".join(f"%25{ord(c):02X}" for c in path_part.lstrip("/"))
        res = f"{p.scheme}://{p.netloc}/%252F{double_encoded_path}"
        if p.query:
            double_encoded_query = "".join(f"%25{ord(c):02X}" for c in p.query)
            res += f"?{double_encoded_query}"
        return res
    elif transform == "hex_param":
        hex_str = norm.encode("utf-8").hex()
        return f"https://track.mail-vn.com/c?u={hex_str}"
    return norm


def apply_benign_transform(url: str, transform: str) -> str:
    u = url.strip()
    norm = u if u.startswith(("http://", "https://")) else f"https://{u}"
    host = extract_host(norm)

    if transform == "identity":
        return norm
    elif transform == "bare_domain":
        return host
    elif transform == "trailing_punct":
        return f"{norm}."
    elif transform == "uppercase":
        return norm.upper()
    elif transform == "defang":
        return norm.replace(".", "[.]")
    return norm


def compute_auroc(labels: list[int], scores: list[float]) -> float:
    """Pure Python AUROC calculation using rank sum (Mann-Whitney U statistic) with ties handling."""
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5

    paired = sorted(zip(scores, labels), key=lambda x: x[0])
    rank_sum = 0.0
    i = 0
    n = len(paired)
    while i < n:
        j = i
        while j < n - 1 and paired[j][0] == paired[j + 1][0]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            if paired[k][1] == 1:
                rank_sum += avg_rank
        i = j + 1

    u_stat = rank_sum - (n_pos * (n_pos + 1)) / 2.0
    return round(u_stat / (n_pos * n_neg), 4)


def predict_baseline(exp_agent: ExplainableAgent, text: str) -> tuple[bool, int]:
    res = exp_agent.explain(text, matched_flags=[], ocr_anomalies=[])
    score = res.get("risk_score", 0)
    has_fake_link = any(
        "link giả mạo" in f.get("factor", "").lower() or "đường link" in f.get("factor", "").lower()
        for f in res.get("risk_breakdown", [])
    )
    is_phishing = has_fake_link or score >= 40
    return is_phishing, score


def predict_url_module(analyzer: Any, text: str) -> tuple[bool, int, set[str]]:
    rep = analyzer.analyze_text(text)
    score = getattr(rep, "max_url_risk", 0)
    is_phishing = score >= 40
    signals: set[str] = set()
    for f in getattr(rep, "findings", []):
        for s in getattr(f, "signals", []):
            code = getattr(s, "code", "")
            if code:
                signals.add(code)
        for ch in getattr(f, "children", []):
            for s in getattr(ch, "signals", []):
                code = getattr(s, "code", "")
                if code:
                    signals.add(code)
    return is_phishing, score, signals


def parse_args():
    parser = argparse.ArgumentParser(description="URL Phishing Evaluation")
    parser.add_argument(
        "--data",
        default=str(PROJECT_ROOT / "data" / "data-phising-VN-ver2" / "splits" / "url_test.csv"),
        help="Path to url_test.csv"
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling")
    parser.add_argument("--sample-phish", type=int, default=1000, help="Number of phishing URLs to sample")
    parser.add_argument(
        "--predictor",
        choices=["baseline", "url_module"],
        default="url_module",
        help="Predictor to evaluate (baseline or url_module, default: url_module)"
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        default=None,
        help="Path to save evaluation results JSON"
    )
    return parser.parse_args()


def run_url_eval(args=None):
    if args is None:
        args = parse_args()

    csv_path = Path(args.data).resolve()
    if not csv_path.exists():
        print(f"[ERROR] Data file not found: {csv_path}")
        sys.exit(1)

    print("=" * 80)
    print(f"URL PHISHING EVALUATION (PREDICTOR: {args.predictor.upper()})")
    print(f"Data file: {csv_path.name}")
    print("=" * 80)

    phishing_rows = []
    benign_rows = []

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lbl = row.get("label", "").strip().lower()
            u = row.get("url", "").strip() or row.get("url_norm", "").strip()
            if not u:
                continue
            if lbl == "phishing":
                phishing_rows.append(u)
            elif lbl == "benign":
                benign_rows.append(u)

    print(f"Total rows read: {len(phishing_rows)} phishing, {len(benign_rows)} benign")

    # Sample phishing with seed
    rng = random.Random(args.seed)
    if len(phishing_rows) > args.sample_phish:
        sample_phish = rng.sample(phishing_rows, args.sample_phish)
    else:
        sample_phish = phishing_rows

    sample_benign = benign_rows
    print(f"Evaluation sample: {len(sample_phish)} phishing (sampled), {len(sample_benign)} benign (all)")

    # Initialize predictor model
    if args.predictor == "baseline":
        model_obj = ExplainableAgent()
    else:
        from codebase.url_analysis import UrlAnalyzer
        from codebase.url_analysis.blacklist import PhishBlacklist
        # Build blacklist strictly excluding test split to prevent data leakage
        blacklist = PhishBlacklist.from_dataset(exclude_splits=["test"])
        model_obj = UrlAnalyzer(blacklist=blacklist)
        print(f"[INFO] Initialized UrlAnalyzer with {len(blacklist.hosts)} blacklist hosts (excluding test split)")

    def do_predict(text: str) -> tuple[bool, int, set[str]]:
        if args.predictor == "baseline":
            is_pred, score = predict_baseline(model_obj, text)
            return is_pred, score, set()
        else:
            return predict_url_module(model_obj, text)

    # 1. Phishing Transforms Evaluation
    phish_transforms = [
        "identity", "bare_domain", "defang", "percent_host", "zero_width",
        "fullwidth", "userinfo_decoy", "open_redirect", "base64_param",
        "shortener", "trailing_punct", "homoglyph_cyrillic", "punycode_idn",
        "ip_decimal", "backslash_confusion", "nested_redirect",
        "double_encoding", "hex_param"
    ]
    phish_results = {}
    for t_name in phish_transforms:
        flagged = 0
        technique_hits = 0
        expected_signals = TECHNIQUE_SIGNALS.get(t_name, set())

        for i, u in enumerate(sample_phish):
            transformed = apply_phishing_transform(u, t_name, i)
            is_pred, score, signals = do_predict(transformed)
            if is_pred:
                flagged += 1
            if expected_signals and bool(signals & expected_signals):
                technique_hits += 1

        recall = round(flagged / len(sample_phish), 4) if sample_phish else 0.0
        tech_rate = round(technique_hits / len(sample_phish), 4) if (expected_signals and sample_phish) else None

        res_item = {
            "recall": recall,
            "flagged": flagged,
            "total": len(sample_phish)
        }
        if tech_rate is not None:
            res_item["technique_detection_rate"] = tech_rate
            res_item["technique_detected_count"] = technique_hits
            print(f"Phishing [{t_name:<20s}]: Recall = {recall * 100:5.1f}% ({flagged}/{len(sample_phish)}) | Tech Detected = {tech_rate * 100:5.1f}% ({technique_hits}/{len(sample_phish)})")
        else:
            print(f"Phishing [{t_name:<20s}]: Recall = {recall * 100:5.1f}% ({flagged}/{len(sample_phish)})")

        phish_results[t_name] = res_item

    # 2. Benign Transforms Evaluation
    benign_transforms = ["identity", "bare_domain", "trailing_punct", "uppercase", "defang"]
    benign_results = {}
    for t_name in benign_transforms:
        fp_count = 0
        for u in sample_benign:
            transformed = apply_benign_transform(u, t_name)
            is_pred, _, _ = do_predict(transformed)
            if is_pred:
                fp_count += 1
        fpr = round(fp_count / len(sample_benign), 4) if sample_benign else 0.0
        benign_results[t_name] = {"fpr": fpr, "fp": fp_count, "total": len(sample_benign)}
        print(f"Benign   [{t_name:<20s}]: FPR    = {fpr * 100:5.1f}% ({fp_count}/{len(sample_benign)})")

    # 3. Overall Identity AUROC & F1
    all_labels = []
    all_scores = []
    all_preds = []

    for u in sample_phish:
        norm = u if u.startswith(("http://", "https://")) else f"http://{u}"
        is_pred, score, _ = do_predict(norm)
        all_labels.append(1)
        all_scores.append(score)
        all_preds.append(1 if is_pred else 0)

    for u in sample_benign:
        norm = u if u.startswith(("http://", "https://")) else f"https://{u}"
        is_pred, score, _ = do_predict(norm)
        all_labels.append(0)
        all_scores.append(score)
        all_preds.append(1 if is_pred else 0)

    auroc = compute_auroc(all_labels, all_scores)

    tp = sum(1 for y, p in zip(all_labels, all_preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(all_labels, all_preds) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(all_labels, all_preds) if y == 1 and p == 0)
    prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * prec * rec / (prec + rec), 4) if (prec + rec) > 0 else 0.0

    avg_phish_aug = round(sum(r["recall"] for r in phish_results.values()) / len(phish_results), 4)
    # Augmentation recall excluding userinfo_decoy and base64_param artifacts
    filtered_transforms = {k: v for k, v in phish_results.items() if k not in ("userinfo_decoy", "base64_param")}
    avg_phish_aug_no_artifact = round(sum(r["recall"] for r in filtered_transforms.values()) / len(filtered_transforms), 4)

    print("-" * 80)
    print(f"OVERALL IDENTITY ({args.predictor.upper()}): Recall = {rec * 100:.1f}%, Precision = {prec * 100:.1f}%, F1 = {f1:.4f}, AUROC = {auroc:.4f}")
    print(f"AUGMENTATION RECALL AVG: All = {avg_phish_aug * 100:.1f}% | Excl. Artifacts = {avg_phish_aug_no_artifact * 100:.1f}%")
    print("=" * 80)

    # Save detailed JSON report
    results_dir = CURRENT_DIR / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    if args.out_path:
        report_file = Path(args.out_path).resolve()
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = results_dir / f"url_eval_{args.predictor}_{ts}.json"

    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_data = {
        "config": f"{args.predictor}",
        "predictor": args.predictor,
        "seed": args.seed,
        "phishing_sample_size": len(sample_phish),
        "benign_sample_size": len(sample_benign),
        "phishing_transforms": phish_results,
        "benign_transforms": benign_results,
        "avg_phish_aug_recall": avg_phish_aug,
        "avg_phish_aug_recall_no_artifact": avg_phish_aug_no_artifact,
        "identity_overall": {
            "recall": rec,
            "precision": prec,
            "f1": f1,
            "auroc": auroc
        }
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f"Saved detailed JSON report to {report_file}")

    # If baseline is run explicitly, update baseline line in RESULTS.md
    if args.predictor == "baseline":
        results_md_path = CURRENT_DIR / "RESULTS.md"
        if results_md_path.exists():
            try:
                baseline_line = (
                    f"| **A-Baseline** | Code gốc ExplainableAgent (offline) | 65.0% (13/20 exact) | "
                    f"{phish_results['identity']['recall']*100:.1f}% | {avg_phish_aug*100:.1f}% | "
                    f"{benign_results['identity']['fpr']*100:.1f}% | {auroc:.4f} |\n"
                )
                content = results_md_path.read_text(encoding="utf-8")
                lines = content.splitlines()
                new_lines = []
                for line in lines:
                    if line.strip().startswith("| **A-Baseline** |"):
                        new_lines.append(baseline_line.strip())
                    else:
                        new_lines.append(line)
                results_md_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                print(f"Updated baseline numbers in {results_md_path}")
            except Exception as e:
                print(f"[Warning] Could not update RESULTS.md: {e}")

    return report_data


if __name__ == "__main__":
    run_url_eval()
