"""Aggregate first-warning scoring under BENCHMARK_PROTOCOL.md.

Prediction JSONL: {id, first_warning: integer|null, status?: ok|error,
resources?: {model_calls?, tokens?, tool_calls?, elapsed_seconds?}}.
No texts, labels, IDs or per-conversation results are printed.
The CLI requires a frozen manifest and verifies the exact dataset hash.
"""

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

RESOURCE_KEYS = {"model_calls", "tokens", "tool_calls", "elapsed_seconds"}
PROTOCOL_VERSION = "1.0"


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def score(records, predictions):
    """Score in memory; the CLI, not this public-fixture function, enforces freeze."""
    by_id = {r["id"]: r for r in records}
    if len(by_id) != len(records) or not records:
        raise ValueError("Dataset is empty or has duplicate identities")
    for record in records:
        gold, n = record["gold"], len(record["input"]["messages"])
        alert = gold["alert_turn"]
        if gold["label"] not in ("scam", "benign") or (
            gold["label"] == "scam" and not (type(alert) is int and 0 <= alert < n)
        ) or (gold["label"] == "benign" and alert is not None):
            raise ValueError("Invalid dataset label or alert reference")
    pairs = set()
    for record in records:
        other_id = record["gold"].get("paired_with")
        if other_id is None:
            continue
        other = by_id.get(other_id)
        if other is None or other["gold"].get("paired_with") != record["id"] or \
                other["gold"]["label"] == record["gold"]["label"]:
            raise ValueError("Invalid dataset pairing")
        pairs.add(tuple(sorted((record["id"], other_id))))

    problems = collections.Counter()
    rows_by_id = collections.defaultdict(list)
    for row in predictions:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            problems["malformed_rows"] += 1
        elif row["id"] not in by_id:
            problems["unknown_id_rows"] += 1
        else:
            rows_by_id[row["id"]].append(row)
    problems["missing_ids"] = len(set(by_id) - set(rows_by_id))
    valid = {}
    resource_values = {k: [] for k in RESOURCE_KEYS}
    for record_id, rows in rows_by_id.items():
        if len(rows) != 1:
            problems["duplicate_ids"] += 1
            continue
        row = rows[0]
        warning = row.get("first_warning")
        status = row.get("status", "ok")
        resources = row.get("resources", {})
        structural = set(row) <= {"id", "first_warning", "status", "resources"} and "first_warning" in row
        structural = structural and status in ("ok", "error") and (
            warning is None or (type(warning) is int and 0 <= warning < len(by_id[record_id]["input"]["messages"]))
        ) and not (status == "error" and warning is not None)
        resource_ok = isinstance(resources, dict) and set(resources) <= RESOURCE_KEYS
        if resource_ok:
            for key, value in resources.items():
                if key == "elapsed_seconds":
                    resource_ok &= type(value) in (int, float) and math.isfinite(value) and value >= 0
                else:
                    resource_ok &= type(value) is int and value >= 0
        if not structural or not resource_ok:
            problems["malformed_rows"] += 1
            continue
        for key, value in resources.items():
            resource_values[key].append(value)
        if status == "error":
            problems["execution_errors"] += 1
            continue
        valid[record_id] = warning

    counts = collections.Counter()
    delays = []
    for record_id, warning in valid.items():
        gold = by_id[record_id]["gold"]
        if gold["label"] == "benign":
            counts["false_positive" if warning is not None else "true_negative"] += 1
        elif warning is None:
            counts["false_negative"] += 1
            counts["missed_scam"] += 1
        else:
            counts["true_positive"] += 1
            delay = warning - gold["alert_turn"]
            if delay < 0:
                counts["premature_scam"] += 1
            else:
                counts["evidence_respecting_scam"] += 1
                counts["exact_boundary_scam"] += delay == 0
                delays.append(delay)
    success = 0
    scored_pairs = 0
    for pair in pairs:
        if not all(record_id in valid for record_id in pair):
            continue
        scored_pairs += 1
        scam_id = next(i for i in pair if by_id[i]["gold"]["label"] == "scam")
        benign_id = next(i for i in pair if i != scam_id)
        warning = valid[scam_id]
        success += warning is not None and warning >= by_id[scam_id]["gold"]["alert_turn"] and valid[benign_id] is None
    complete = len(valid) == len(records) and not any(problems.values())
    classes = collections.Counter(r["gold"]["label"] for r in records)
    tp, fp, fn, tn = (counts[k] for k in ("true_positive", "false_positive", "false_negative", "true_negative"))
    metrics = None
    if complete:
        metrics = {
            "conversation_precision": ratio(tp, tp + fp), "conversation_recall": ratio(tp, tp + fn),
            "conversation_f1": ratio(2 * tp, 2 * tp + fp + fn),
            "conversation_accuracy": ratio(tp + tn, len(records)),
            "benign_false_alarm_rate": ratio(fp, classes["benign"]),
            "premature_warning_rate": ratio(counts["premature_scam"], classes["scam"]),
            "miss_rate": ratio(counts["missed_scam"], classes["scam"]),
            "evidence_respecting_detection_rate": ratio(counts["evidence_respecting_scam"], classes["scam"]),
            "exact_boundary_detection_rate": ratio(counts["exact_boundary_scam"], classes["scam"]),
            "warning_delay_mean_messages": statistics.mean(delays) if delays else None,
            "warning_delay_median_messages": statistics.median(delays) if delays else None,
            "warning_delay_denominator": len(delays),
            "paired_near_miss_success_rate": ratio(success, len(pairs)),
        }
    return {
        "status": "complete" if complete else "incomplete_predictions",
        "conversations": len(records), "classes": dict(classes), "valid_predictions": len(valid),
        "problems": dict(problems), "metrics": metrics,
        "observed_counts": dict(counts), "pairs": len(pairs), "scored_pairs": scored_pairs,
        "successful_pairs": success,
        "unscored_by_label": dict(collections.Counter(by_id[i]["gold"]["label"] for i in set(by_id) - set(valid))),
        "resources": {key: {"reported_conversations": len(values), "total": sum(values) if values else None,
                            "mean": statistics.mean(values) if values else None}
                      for key, values in sorted(resource_values.items())},
        "limitations": [
            "Incomplete or erroneous predictions withhold primary metrics; observed counts are diagnostics only.",
            "Zero-denominator quantities are null; delay is conditional on evidence-respecting detections.",
            "Warning-index scoring does not verify prefix isolation or resource accounting in the detector.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--run-manifest", type=Path, required=True,
                        help="Binds dataset_sha256, testset_version and predictions_sha256 to the run")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if manifest.get("status") != "frozen" or not isinstance(manifest.get("testset_version"), str):
            raise ValueError("Manifest does not declare a frozen dataset")
        protocol_path = Path(manifest.get("protocol_path", "BENCHMARK_PROTOCOL.md"))
        if protocol_path.is_absolute() or ".." in protocol_path.parts or manifest.get("protocol_version") != PROTOCOL_VERSION:
            raise ValueError("Unsupported protocol identity")
        protocol_raw = args.manifest.parent.joinpath(protocol_path).read_bytes()
        protocol_sha = hashlib.sha256(protocol_raw).hexdigest()
        if manifest.get("protocol_sha256") != protocol_sha:
            raise ValueError("Frozen protocol hash mismatch")
        raw = args.data.read_bytes()
        data_sha = hashlib.sha256(raw).hexdigest()
        if manifest.get("conversations_sha256") != data_sha:
            raise ValueError("Frozen dataset hash mismatch")
        prediction_raw = args.predictions.read_bytes()
        prediction_sha = hashlib.sha256(prediction_raw).hexdigest()
        run_raw = args.run_manifest.read_bytes()
        run = json.loads(run_raw)
        if run.get("dataset_sha256") != data_sha or run.get("predictions_sha256") != prediction_sha \
                or run.get("testset_version") != manifest["testset_version"]:
            raise ValueError("Prediction run identity mismatch")
        records = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
        predictions = []
        for line in prediction_raw.decode("utf-8").splitlines():
            if line.strip():
                try:
                    predictions.append(json.loads(line))
                except json.JSONDecodeError:
                    predictions.append(None)
        report = score(records, predictions)
        report.update(dataset_sha256=data_sha, testset_version=manifest.get("testset_version"),
                      predictions_sha256=prediction_sha, run_manifest_sha256=hashlib.sha256(run_raw).hexdigest(),
                      protocol_sha256=protocol_sha, protocol_version=PROTOCOL_VERSION,
                      scorer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
        return 0 if report["status"] == "complete" else 1
    except (OSError, ValueError, KeyError, TypeError):
        print("Scoring refused: invalid dataset, manifest or input artifact. No records displayed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
