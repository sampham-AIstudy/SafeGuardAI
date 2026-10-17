import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

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

RUN_EVAL_PATH = CURRENT_DIR / "run_eval.py"
URL_EVAL_PATH = CURRENT_DIR / "url_eval.py"
GOLDEN_V1_PATH = CURRENT_DIR / "golden_set.json"
GOLDEN_V2_PATH = CURRENT_DIR / "golden_set_v2.json"
RESULTS_MD_PATH = CURRENT_DIR / "RESULTS.md"

MARKER_START = "<!-- ABLATION:START -->"
MARKER_END = "<!-- ABLATION:END -->"

# Known baseline numbers for Config A (Phase 0, commit 250d938)
CONFIG_A_DATA: dict[str, Any] = {
    "config": "A (Phase 0)",
    "description": "Đo ở Phase 0 (commit 250d938), không chạy lại",
    "macro_f1": "—",
    "v1_exact": "65.0% (13/20)",
    "v2_exact": "40.3%",
    "v2_high_recall": "31.7%",
    "v2_fpr_benign": "18.2%",
    "v2_crit_strict": "40.0%",
    "p95_ms": "—",
    "url_id_recall": "22.1%",
    "url_recall_best_f1": "—",
    "url_fpr_best_f1": "—",
    "url_aug_recall_avg": "26.9%",
    "url_aug_recall_no_art": "10.7%",
    "url_benign_fpr": "7.4%",
    "url_auroc": "0.5790",
}


def build_subprocess_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """Build isolated environment for evaluation subprocesses."""
    env = os.environ.copy()
    env["SAFEGUARD_OFFLINE"] = "1"
    env["SAFEGUARD_DB"] = "off"
    env["SAFEGUARD_NETWORK"] = "off"
    # Blank all API keys to avoid external calls or token leakage
    for k in [
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "URLSCAN_API_KEY",
        "VIRUSTOTAL_API_KEY",
    ]:
        env[k] = ""
    if extra_env:
        env.update(extra_env)
    return env


def run_command(cmd: list[str], env: dict[str, str], timeout_s: int = 180) -> subprocess.CompletedProcess:
    """Run evaluation command in foreground with timeout."""
    return subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_s,
        check=False,
    )


def evaluate_config(
    config_name: str,
    extra_env: dict[str, str],
    url_predictor: str,
    sample_phish: int,
    work_dir: Path,
) -> dict[str, Any]:
    """Run all evaluations for a single configuration in clean subprocesses."""
    env = build_subprocess_env(extra_env)
    py_bin = sys.executable

    print(f"\n[{config_name}] Running evaluations (work_dir: {work_dir})...")

    # 1. Golden v1 (all 20 cases)
    out_v1 = work_dir / f"{config_name.lower()}_v1.json"
    cmd_v1 = [py_bin, str(RUN_EVAL_PATH), "--set", str(GOLDEN_V1_PATH), "--out", str(out_v1)]
    run_command(cmd_v1, env)

    # 2. Golden v2 (all 72 cases)
    out_v2_all = work_dir / f"{config_name.lower()}_v2_all.json"
    cmd_v2_all = [py_bin, str(RUN_EVAL_PATH), "--set", str(GOLDEN_V2_PATH), "--split", "all", "--out", str(out_v2_all)]
    run_command(cmd_v2_all, env)

    # 3. Golden v2 dev (41 cases)
    out_v2_dev = work_dir / f"{config_name.lower()}_v2_dev.json"
    cmd_v2_dev = [py_bin, str(RUN_EVAL_PATH), "--set", str(GOLDEN_V2_PATH), "--split", "dev", "--out", str(out_v2_dev)]
    run_command(cmd_v2_dev, env)

    # 4. Golden v2 test (31 cases)
    out_v2_test = work_dir / f"{config_name.lower()}_v2_test.json"
    cmd_v2_test = [py_bin, str(RUN_EVAL_PATH), "--set", str(GOLDEN_V2_PATH), "--split", "test", "--out", str(out_v2_test)]
    run_command(cmd_v2_test, env)

    # 5. URL evaluation
    out_url = work_dir / f"{config_name.lower()}_url.json"
    cmd_url = [
        py_bin,
        str(URL_EVAL_PATH),
        "--predictor",
        url_predictor,
        "--sample-phish",
        str(sample_phish),
        "--out",
        str(out_url),
    ]
    run_command(cmd_url, env)

    # Read back outputs
    v1_metrics = {}
    if out_v1.exists():
        try:
            with open(out_v1, "r", encoding="utf-8") as f:
                v1_metrics = json.load(f).get("metrics", {})
        except Exception:
            pass

    v2_all_metrics = {}
    if out_v2_all.exists():
        try:
            with open(out_v2_all, "r", encoding="utf-8") as f:
                v2_all_metrics = json.load(f).get("metrics", {})
        except Exception:
            pass

    v2_dev_metrics = {}
    if out_v2_dev.exists():
        try:
            with open(out_v2_dev, "r", encoding="utf-8") as f:
                v2_dev_metrics = json.load(f).get("metrics", {})
        except Exception:
            pass

    v2_test_metrics = {}
    if out_v2_test.exists():
        try:
            with open(out_v2_test, "r", encoding="utf-8") as f:
                v2_test_metrics = json.load(f).get("metrics", {})
        except Exception:
            pass

    url_data = {}
    if out_url.exists():
        try:
            with open(out_url, "r", encoding="utf-8") as f:
                url_data = json.load(f)
        except Exception:
            pass

    # Extract formatted metric strings
    v1_hits = v1_metrics.get("passed_cases_exact", 0)
    v1_total = v1_metrics.get("total_cases", 0)
    v1_acc = v1_metrics.get("accuracy_exact", 0.0) * 100
    v1_str = f"{v1_acc:.1f}% ({v1_hits}/{v1_total})" if v1_total > 0 else "n/a"

    v2_acc = v2_all_metrics.get("accuracy_exact", 0.0) * 100
    v2_f1 = v2_all_metrics.get("macro_f1", 0.0)
    v2_high = v2_all_metrics.get("binary_high_plus", {}).get("recall", 0.0) * 100
    v2_fpr = v2_all_metrics.get("fpr_benign", 0.0) * 100
    v2_crit = v2_all_metrics.get("critical_recall_strict", 0.0) * 100
    p95 = v2_all_metrics.get("latency", {}).get("p95_ms", 0.0)

    url_id_rec = url_data.get("identity_overall", {}).get("recall", 0.0) * 100
    best_f1_dict = url_data.get("best_f1", {})
    if best_f1_dict and "recall" in best_f1_dict and "fpr" in best_f1_dict:
        url_rec_best = f"{best_f1_dict.get('recall', 0.0) * 100:.1f}%"
        url_fpr_best = f"{best_f1_dict.get('fpr', 0.0) * 100:.1f}%"
    else:
        url_rec_best = "—"
        url_fpr_best = "—"

    url_aug_rec = url_data.get("avg_phish_aug_recall", 0.0) * 100
    url_aug_no_art = url_data.get("avg_phish_aug_recall_no_artifact", 0.0) * 100
    url_fpr = url_data.get("benign_transforms", {}).get("identity", {}).get("fpr", 0.0) * 100
    url_auroc = url_data.get("identity_overall", {}).get("auroc", 0.0)

    return {
        "config": config_name,
        "v1_metrics": v1_metrics,
        "v2_all_metrics": v2_all_metrics,
        "v2_dev_metrics": v2_dev_metrics,
        "v2_test_metrics": v2_test_metrics,
        "url_data": url_data,
        "formatted": {
            "v1_exact": v1_str,
            "v2_exact": f"{v2_acc:.1f}%",
            "macro_f1": f"{v2_f1:.4f}",
            "v2_high_recall": f"{v2_high:.1f}%",
            "v2_fpr_benign": f"{v2_fpr:.1f}%",
            "v2_crit_strict": f"{v2_crit:.1f}%",
            "p95_ms": f"{p95:.1f}",
            "url_id_recall": f"{url_id_rec:.1f}%",
            "url_recall_best_f1": url_rec_best,
            "url_fpr_best_f1": url_fpr_best,
            "url_aug_recall_avg": f"{url_aug_rec:.1f}%",
            "url_aug_recall_no_art": f"{url_aug_no_art:.1f}%",
            "url_benign_fpr": f"{url_fpr:.1f}%",
            "url_auroc": f"{url_auroc:.4f}",
        },
    }


def format_ablation_table(records: list[dict[str, Any]]) -> str:
    """Format markdown ablation table and notes from evaluation records."""
    headers = [
        "Cấu hình",
        "Mô tả / Nguồn",
        "Macro-F1 (v2)",
        "Golden v1 Exact",
        "Golden v2 Exact",
        "Recall HIGH+ (v2)",
        "FPR>=MED (v2)",
        "Recall CRIT chặt (v2)",
        "p95 (ms)",
        "URL Identity Recall",
        "URL recall@bestF1",
        "URL FPR@bestF1",
        "URL Aug Recall (Avg / No-art)",
        "URL Benign FPR",
        "AUROC",
    ]
    lines = [
        f"| {' | '.join(headers)} |",
        f"| {' | '.join(['---'] * len(headers))} |",
    ]

    for rec in records:
        fmt = rec.get("formatted", rec)
        cfg = rec.get("config", "")
        desc = rec.get("description", "")
        if not desc:
            if "B" in cfg:
                desc = "SAFEGUARD_URL_MODULE=off (Phase 1 + T1.6)"
            elif "C" in cfg:
                desc = "Module URL deobfuscation bật (mặc định Phase 2)"
            else:
                desc = "—"

        row = [
            f"**{cfg}**",
            desc,
            str(fmt.get("macro_f1", "—")),
            str(fmt.get("v1_exact", "—")),
            str(fmt.get("v2_exact", "—")),
            str(fmt.get("v2_high_recall", "—")),
            str(fmt.get("v2_fpr_benign", "—")),
            str(fmt.get("v2_crit_strict", "—")),
            str(fmt.get("p95_ms", "—")),
            str(fmt.get("url_id_recall", "—")),
            str(fmt.get("url_recall_best_f1", "—")),
            str(fmt.get("url_fpr_best_f1", "—")),
            f"{fmt.get('url_aug_recall_avg', '—')} / {fmt.get('url_aug_recall_no_art', '—')}",
            str(fmt.get("url_benign_fpr", "—")),
            str(fmt.get("url_auroc", "—")),
        ]
        lines.append(f"| {' | '.join(row)} |")

    # Build note section with dev/test breakdowns
    notes = [
        "",
        "> [!NOTE]",
        "> - **Cấu hình A (Phase 0)**: Đo ở Phase 0 (commit 250d938), giữ nguyên làm đối chứng, không chạy lại.",
        "> - **Cấu hình B (URL Off)**: Tắt module URL (`SAFEGUARD_URL_MODULE=off`), giữ nguyên logic ExplainableAgent cũ và cải tiến Phase 1.",
        "> - **Cấu hình C (URL On)**: Bật module URL Deobfuscation & Analysis đầy đủ (WhatWG URL parsing, multi-layer decoding, IDN homoglyph, Brand catalog, PhishBlacklist train+val).",
        "> - **Ngưỡng tối ưu**: Cột `URL recall@bestF1` và `URL FPR@bestF1` đo hiệu năng tại ngưỡng tối ưu F1 chọn trên tập validation (url_val.csv), tránh chọn ngưỡng trên test.",
    ]

    for rec in records:
        cfg = rec.get("config", "")
        dev_m = rec.get("v2_dev_metrics", {})
        test_m = rec.get("v2_test_metrics", {})
        if dev_m and test_m:
            dev_acc = dev_m.get("accuracy_exact", 0.0) * 100
            dev_fpr = dev_m.get("fpr_benign", 0.0) * 100
            dev_crit = dev_m.get("critical_recall_strict", 0.0) * 100

            test_acc = test_m.get("accuracy_exact", 0.0) * 100
            test_fpr = test_m.get("fpr_benign", 0.0) * 100
            test_crit = test_m.get("critical_recall_strict", 0.0) * 100

            notes.append(
                f"> - **Chi tiết v2 {cfg}**: "
                f"Dev exact={dev_acc:.1f}%, FPR={dev_fpr:.1f}%, Crit={dev_crit:.1f}% | "
                f"Test exact={test_acc:.1f}%, FPR={test_fpr:.1f}%, Crit={test_crit:.1f}%"
            )

    return "\n".join(lines) + "\n" + "\n".join(notes) + "\n"


def update_results_markdown(original_content: str, table_md: str) -> str:
    """Safely replace or insert ablation table between markers in RESULTS.md."""
    wrapped_block = f"{MARKER_START}\n\n## Bảng so sánh Ablation Module URL\n\n{table_md.strip()}\n\n{MARKER_END}"

    if MARKER_START in original_content and MARKER_END in original_content:
        start_idx = original_content.index(MARKER_START)
        end_idx = original_content.index(MARKER_END) + len(MARKER_END)
        return original_content[:start_idx] + wrapped_block + original_content[end_idx:]
    else:
        # Append to the end cleanly
        return original_content.rstrip() + "\n\n" + wrapped_block + "\n"


def parse_args():
    parser = argparse.ArgumentParser(description="SafeGuard AI Ablation Study")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quickly with sample-phish 300 (default: 1000)"
    )
    parser.add_argument(
        "--write-results",
        action="store_true",
        help="Update eval/RESULTS.md between ABLATION markers"
    )
    parser.add_argument(
        "--config",
        choices=["all", "B", "C"],
        default="all",
        help="Configuration to run (default: all)"
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        default=None,
        help="Path to save ablation JSON results"
    )
    return parser.parse_args()


def run_ablation():
    args = parse_args()
    sample_phish = 300 if args.quick else 1000

    print("=" * 80)
    print("SAFEGUARD AI — ABLATION EVALUATION SUITE")
    print(f"Mode: {'QUICK (sample_phish=300)' if args.quick else 'FULL (sample_phish=1000)'}")
    print("=" * 80)

    records: list[dict[str, Any]] = [CONFIG_A_DATA]

    with tempfile.TemporaryDirectory(prefix="safeguard_ablation_") as tmp_dir_str:
        work_dir = Path(tmp_dir_str)

        # Config B: SAFEGUARD_URL_MODULE=off
        if args.config in ("all", "B"):
            rec_b = evaluate_config(
                config_name="B (URL Off)",
                extra_env={"SAFEGUARD_URL_MODULE": "off"},
                url_predictor="baseline",
                sample_phish=sample_phish,
                work_dir=work_dir,
            )
            records.append(rec_b)

        # Config C: SAFEGUARD_URL_MODULE=on (default)
        if args.config in ("all", "C"):
            rec_c = evaluate_config(
                config_name="C (URL On)",
                extra_env={"SAFEGUARD_URL_MODULE": "on"},
                url_predictor="url_module",
                sample_phish=sample_phish,
                work_dir=work_dir,
            )
            records.append(rec_c)

    table_md = format_ablation_table(records)
    print("\n" + "=" * 80)
    print("ABLATION RESULTS TABLE:")
    print("=" * 80)
    print(table_md)

    # Save JSON report
    results_dir = CURRENT_DIR / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    if args.out_path:
        out_file = Path(args.out_path).resolve()
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = results_dir / f"ablation_{ts}.json"

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "sample_phish": sample_phish,
            "records": records,
        }, f, indent=2, ensure_ascii=False)
    print(f"\nSaved ablation summary to {out_file}")

    # Write to RESULTS.md if requested
    if args.write_results:
        original = ""
        if RESULTS_MD_PATH.exists():
            original = RESULTS_MD_PATH.read_text(encoding="utf-8")
        updated = update_results_markdown(original, table_md)
        RESULTS_MD_PATH.write_text(updated, encoding="utf-8")
        print(f"Successfully updated ablation block in {RESULTS_MD_PATH}")


if __name__ == "__main__":
    run_ablation()
