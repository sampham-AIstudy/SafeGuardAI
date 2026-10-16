import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure UTF-8 stdout/stderr on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root in sys.path relative to this file
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from codebase.config import get_settings
from eval.metrics import compute_all_metrics


def parse_args():
    parser = argparse.ArgumentParser(description="SafeGuard AI Benchmark Evaluation")
    parser.add_argument(
        "--set",
        dest="set_path",
        default=str(CURRENT_DIR / "golden_set.json"),
        help="Path to evaluation dataset JSON file"
    )
    parser.add_argument(
        "--mode",
        choices=["offline", "llm"],
        default="offline",
        help="Execution mode (offline or llm, default: offline)"
    )
    parser.add_argument(
        "--no-sleep",
        action="store_true",
        help="Disable sleep delay between requests"
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        default=None,
        help="Path to save evaluation results JSON"
    )
    parser.add_argument(
        "--split",
        choices=["dev", "test", "all"],
        default="all",
        help="Dataset split to evaluate (dev, test, or all, default: all)"
    )
    return parser.parse_args()


def reset_memory(orchestrator, session_id: str = "eval_session"):
    if hasattr(orchestrator.memory_agent, "reset"):
        orchestrator.memory_agent.reset(session_id)
    else:
        orchestrator.memory_agent.history = []
        if hasattr(orchestrator.memory_agent, "escalation_flags"):
            orchestrator.memory_agent.escalation_flags = []


def run_evaluation():
    args = parse_args()

    # Apply execution mode environment
    if args.mode == "offline":
        os.environ["SAFEGUARD_OFFLINE"] = "1"
        os.environ["SAFEGUARD_DB"] = "off"
        os.environ["SAFEGUARD_NETWORK"] = "off"
    else:
        os.environ["SAFEGUARD_OFFLINE"] = "0"

    get_settings(refresh=True)

    # Delay imports of orchestrator until env is set
    from codebase.orchestrator import SafeGuardOrchestrator

    set_file = Path(args.set_path).resolve()
    if not set_file.exists():
        print(f"[ERROR] Evaluation set not found at {set_file}")
        sys.exit(2)

    with open(set_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data, dict):
            raw_cases = data.get("golden_set") or data.get("cases") or []
        elif isinstance(data, list):
            raw_cases = data
        else:
            raw_cases = []

    # Filter by split if specified
    if args.split != "all":
        cases = [c for c in raw_cases if c.get("split", "dev") == args.split]
    else:
        cases = raw_cases

    if not cases:
        print(f"[ERROR] No cases found in {set_file} for split '{args.split}'")
        sys.exit(2)

    orchestrator = SafeGuardOrchestrator()

    dataset_name = set_file.stem
    tag = f"{dataset_name}_{args.mode}"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print("=" * 80)
    print(f"SAFEGUARD AI BENCHMARK EVALUATION — {dataset_name.upper()}")
    print(f"Mode: {args.mode.upper()} | Split: {args.split} | Total Cases: {len(cases)}")
    print("=" * 80)

    results = []
    for idx, case in enumerate(cases):
        case_id = case.get("id", f"CASE_{idx+1:02d}")
        session_id = f"eval_{case_id}"
        reset_memory(orchestrator, session_id)

        t_start = time.perf_counter()
        turns = case.get("turns")
        if turns and isinstance(turns, list):
            last_res = None
            for t_idx, turn_text in enumerate(turns):
                last_res = orchestrator.process_request(
                    turn_text,
                    session_id=session_id,
                    persist=False
                )
            res = last_res
        else:
            input_text = case.get("input_text", "")
            res = orchestrator.process_request(
                input_text,
                session_id=session_id,
                persist=False
            )

        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        predicted_level = res.get("decision", {}).get("risk_level", "LOW")
        score = res.get("risk_score", 0)
        expected_level = case.get("expected_risk_level", "LOW")
        min_expected_score = case.get("min_expected_score", 0)

        is_exact_match = (predicted_level == expected_level)
        is_lenient_match = is_exact_match or (
            expected_level in ("HIGH", "CRITICAL")
            and predicted_level in ("HIGH", "CRITICAL")
            and score >= min_expected_score
        )
        status_sym = "PASS" if is_exact_match else "FAIL"

        case_record = {
            "id": case_id,
            "category": case.get("category", "General"),
            "expected_risk_level": expected_level,
            "predicted_risk_level": predicted_level,
            "risk_score": score,
            "min_expected_score": min_expected_score,
            "is_exact_match": is_exact_match,
            "is_lenient_match": is_lenient_match,
            "latency_ms": latency_ms,
            "execution_path": res.get("execution_path", "unknown"),
            "split": case.get("split", "dev"),
            "tags": case.get("tags", [])
        }
        results.append(case_record)

        print(f"[{status_sym}] {case_id:12s} | Pred: {predicted_level:8s} ({score:2d}%) | Expected: {expected_level:8s} | {latency_ms:6.1f}ms")

        # Sleep only when in LLM mode and not disabled
        if args.mode == "llm" and not args.no_sleep and idx < len(cases) - 1:
            time.sleep(3.5)

    # Compute all metrics
    metrics = compute_all_metrics(results)

    # Print summary
    print("\n" + "=" * 80)
    print("EVALUATION RESULTS SUMMARY")
    print(f"Dataset: {dataset_name} ({len(cases)} cases) | Mode: {args.mode}")
    print(f"Accuracy (Exact Match):        {metrics['accuracy'] * 100:.1f}% ({metrics['passed_cases_exact']}/{len(cases)}) (95% CI: [{metrics['accuracy_ci_95'][0]*100:.1f}%, {metrics['accuracy_ci_95'][1]*100:.1f}%])")
    print(f"Accuracy (Lenient Match):      {metrics['accuracy_lenient'] * 100:.1f}% ({metrics['passed_cases_lenient']}/{len(cases)})")
    print(f"Accuracy (Within <=1 step):    {metrics['accuracy_within_one_step'] * 100:.1f}%")
    print(f"Macro-F1 Score:                {metrics['macro_f1']:.4f} (95% CI: [{metrics['macro_f1_ci_95'][0]:.4f}, {metrics['macro_f1_ci_95'][1]:.4f}])")
    crit_s = metrics["critical_recall_strict"]
    crit_s_str = f"{crit_s * 100:.1f}%" if crit_s is not None else "n/a"
    crit_l = metrics["critical_recall_loose"]
    crit_l_str = f"{crit_l * 100:.1f}%" if crit_l is not None else "n/a"
    print(f"Critical Recall (Strict):      {crit_s_str}")
    print(f"Critical Recall (Loose):       {crit_l_str}")
    print(f"Binary HIGH+ F1:               {metrics['binary_high_plus']['f1']:.4f} (Recall: {metrics['binary_high_plus']['recall']*100:.1f}%, Prec: {metrics['binary_high_plus']['precision']*100:.1f}%)")
    print(f"Binary >=MEDIUM F1:            {metrics['binary_medium_plus']['f1']:.4f} (Recall: {metrics['binary_medium_plus']['recall']*100:.1f}%, Prec: {metrics['binary_medium_plus']['precision']*100:.1f}%)")
    print(f"FPR on Benign:                 {metrics['fpr_benign'] * 100:.1f}%")
    if metrics["latency"]:
        print(f"Latency: p50={metrics['latency']['p50_ms']}ms | p95={metrics['latency']['p95_ms']}ms | mean={metrics['latency']['mean_ms']}ms")

    print("-" * 80)
    print("Confusion Matrix (Rows: Expected, Columns: Predicted):")
    header = "Expected \\ Pred".ljust(18) + "".join(f"{c:>10}" for c in ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    print(header)
    for exp_cls in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        row = f"{exp_cls:<18}" + "".join(f"{metrics['confusion_matrix'][exp_cls][p]:>10}" for p in ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        print(row)
    print("=" * 80)

    # Determine save path
    if args.out_path:
        out_file = Path(args.out_path).resolve()
    else:
        results_dir = CURRENT_DIR / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        out_file = results_dir / f"{tag}_{timestamp}.json"

    out_file.parent.mkdir(parents=True, exist_ok=True)
    report_data = {
        "timestamp": timestamp,
        "dataset": str(set_file.name),
        "mode": args.mode,
        "split": args.split,
        "metrics": metrics,
        "results": results
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    print(f"Saved evaluation report to: {out_file}")

    # Check Quality Bar: accuracy >= 85% and critical_recall_strict == 100%
    crit_ok = True if crit_s is None else (crit_s >= 1.0)
    quality_passed = (metrics["accuracy"] >= 0.85) and crit_ok
    if quality_passed:
        print("QUALITY BAR STATUS: PASSED")
        sys.exit(0)
    else:
        print("QUALITY BAR STATUS: NEEDS FINE-TUNING (Accuracy < 85% or Critical Recall < 100%)")
        sys.exit(1)


if __name__ == "__main__":
    run_evaluation()
