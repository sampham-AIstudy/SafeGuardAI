"""Audit public CSV structure and aggregates without printing conversation records."""

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import statistics
import unicodedata
import urllib.request


REVISION = "709db2b6c37f424c3070f29138abb33971e21ab9"
DATASET = "BothBosu/multi-agent-scam-conversation"
FILES = ["README.md", "agent_conversation_all.csv",
         "agent_conversation_train.csv", "agent_conversation_test.csv"]
from safeguard.evaluation.paths import ROOT as PROJECT, archive, output, private_output, inputs, release_input, local_artifact, QC, SCORER, save_json

HERE = output("bothbosu")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    tmp.replace(path)


def normalized(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def auc(values):
    """Positive score outranks a negative; ties contribute one half."""
    buckets = defaultdict(Counter)
    for score, label in values:
        buckets[score][label] += 1
    pos = sum(c[1] for c in buckets.values())
    neg = sum(c[0] for c in buckets.values())
    if not pos or not neg:
        return None
    lower_neg = 0
    wins = 0
    for score in sorted(buckets):
        counts = buckets[score]
        wins += counts[1] * (lower_neg + counts[0] / 2)
        lower_neg += counts[0]
    return wins / (pos * neg)


def describe(values):
    if not values:
        return None
    return {"count": len(values), "min": min(values),
            "median": statistics.median(values), "mean": statistics.mean(values),
            "max": max(values)}


def constants(labels):
    p, n = labels[1], labels[0]
    return {
        "always_scam": {"accuracy": p / (p + n), "scam_recall": 1 if p else None,
                        "positive_f1": 2 * p / (2 * p + n),
                        "false_positive_rate": 1 if n else None},
        "always_non_scam": {"accuracy": n / (p + n), "scam_recall": 0 if p else None,
                            "positive_f1": 0 if p else None,
                            "false_positive_rate": 0 if n else None},
    }


def read_csv(path):
    raw = path.read_bytes()
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True)
    columns = set(reader.fieldnames or [])
    required = {"dialogue", "personality", "type"}
    references = columns & {"label", "labels"}
    if not required <= columns or len(references) != 1:
        raise ValueError("Required CSV columns missing: " + path.name)
    label_column = references.pop()
    rows = list(reader)
    if not rows:
        raise ValueError("Empty dataset: " + path.name)
    if any(None in row or any(v is None for v in row.values()) for row in rows):
        raise ValueError("Ragged CSV: " + path.name)
    for row in rows:
        row["label"] = row[label_column]
        if row["label"].strip() not in {"0", "1"}:
            raise ValueError("Nonbinary reference: " + path.name)
    return reader.fieldnames, rows


def row_keys(rows, mode):
    if mode == "row":
        return Counter(digest(json.dumps({k: r[k] for k in
            ["dialogue", "personality", "type", "label"]}, sort_keys=True).encode()) for r in rows)
    return Counter(digest((normalized(r["dialogue"]) if mode == "normalized"
                           else r["dialogue"]).encode()) for r in rows)


def summarize(rows):
    labels = Counter(int(r["label"]) for r in rows)
    words = [(len(re.findall(r"\w+", r["dialogue"])), int(r["label"])) for r in rows]
    types = defaultdict(Counter)
    personalities = defaultdict(Counter)
    reference_conflicts = defaultdict(set)
    for row in rows:
        label = int(row["label"])
        types[row["type"]][label] += 1
        personalities[row["personality"]][label] += 1
        reference_conflicts[digest(normalized(row["dialogue"]).encode())].add(label)
    markers = ["Suspect", "Innocent", "TERMINATE", "scammer", "scam", "fraud"]
    return {
        "rows": len(rows), "labels": dict(labels),
        "empty_fields": {k: sum(not r[k].strip() for r in rows)
                         for k in ["dialogue", "personality", "type", "label"]},
        "type_by_label": dict(types), "personality_by_label": dict(personalities),
        "word_count_definition": "Number of Unicode regex \\w+ matches in serialized dialogue",
        "word_count_by_label": {label: describe([s for s, y in words if y == label])
                                for label in [0, 1]},
        "longer_dialogue_auc": auc(words),
        "duplicate_excess_rows": {mode: len(rows) - len(row_keys(rows, mode))
                                  for mode in ["row", "exact", "normalized"]},
        "normalized_dialogue_groups_with_both_labels": sum(len(v) > 1 for v in reference_conflicts.values()),
        "dialogue_marker_presence_by_label": {
            marker: {label: sum(int(r["label"]) == label and bool(re.search(
                r"\b" + re.escape(marker) + r"\b", r["dialogue"], re.I)) for r in rows)
                for label in [0, 1]} for marker in markers},
        "constant_references": constants(labels),
    }


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    lock_path = HERE / "release-lock.json"
    if args.download:
        args.data_dir.mkdir(parents=True, exist_ok=True)
        lock = json.loads(lock_path.read_text()) if lock_path.exists() else {
            "dataset": DATASET, "revision": REVISION, "review_date": "2026-11-07", "files": {}}
        if (lock["dataset"], lock["revision"]) != (DATASET, REVISION):
            raise ValueError("Existing lock identifies different inputs")
        for name in FILES:
            path = args.data_dir / name
            if name in lock["files"]:
                if not path.exists() or digest(path.read_bytes()) != lock["files"][name]["sha256"]:
                    raise ValueError("Previously downloaded bytes changed: " + name)
                print("Verified saved input: " + name, flush=True)
                continue
            url = f"https://huggingface.co/datasets/{DATASET}/resolve/{REVISION}/{name}"
            with urllib.request.urlopen(url, timeout=30) as response:
                raw = response.read(50_000_001)
                if len(raw) > 50_000_000:
                    raise ValueError("Download exceeded operational byte limit")
            tmp = path.with_suffix(path.suffix + ".part")
            tmp.write_bytes(raw)
            tmp.replace(path)
            lock["files"][name] = {"url": url,
                                   "bytes": len(raw), "sha256": digest(raw)}
            write_json(lock_path, lock)
            print(f"Retrieved {name}: {len(raw)} bytes", flush=True)
    lock = json.loads(lock_path.read_text())
    for name in FILES:
        raw = (args.data_dir / name).read_bytes()
        if len(raw) != lock["files"][name]["bytes"] or digest(raw) != lock["files"][name]["sha256"]:
            raise ValueError("Input verification failed: " + name)
    splits = {}
    headers = {}
    for split in ["all", "train", "test"]:
        headers[split], splits[split] = read_csv(args.data_dir / f"agent_conversation_{split}.csv")
    overlap = {}
    for mode in ["row", "exact", "normalized"]:
        all_keys, train, test = [row_keys(splits[s], mode) for s in ["all", "train", "test"]]
        overlap[mode] = {"train_test_common_groups": len(train.keys() & test.keys()),
                         "train_rows_in_shared_groups": sum(train[k] for k in train.keys() & test.keys()),
                         "test_rows_in_shared_groups": sum(test[k] for k in train.keys() & test.keys()),
                         "all_equals_train_plus_test_as_multiset": all_keys == train + test}
    train_types = defaultdict(Counter)
    train_personalities = defaultdict(Counter)
    for row in splits["train"]:
        train_types[row["type"]][int(row["label"])] += 1
        train_personalities[row["personality"]][int(row["label"])] += 1
    metadata_rules = {}
    for field, mapping in [("type", train_types), ("personality", train_personalities)]:
        majority = {key: max([0, 1], key=lambda y: (counts[y], -y)) for key, counts in mapping.items()}
        covered = [r for r in splits["test"] if r[field] in majority]
        metadata_rules[field] = {"covered_test_rows": len(covered),
                                "correct_test_rows": sum(majority[r[field]] == int(r["label"]) for r in covered),
                                "input_allowed_for_detector": False,
                                "interpretation": "Metadata association diagnostic, not text-only detector performance"}
    train_auc = auc([(len(re.findall(r"\w+", r["dialogue"])), int(r["label"])) for r in splits["train"]])
    direction = 1 if train_auc >= .5 else -1
    test_auc = auc([(direction * len(re.findall(r"\w+", r["dialogue"])), int(r["label"])) for r in splits["test"]])
    report = {"review_date": "2026-11-07", "dataset": DATASET, "revision": REVISION,
              "scope": "CPU mechanical aggregate audit; no LLM/engine inference or semantic relabeling",
              "input_lock_sha256": digest(lock_path.read_bytes()), "script_sha256": digest(Path(__file__).read_bytes()),
              "headers": headers, "splits": {s: summarize(r) for s, r in splits.items()},
              "schema_note": "Pinned CSV uses labels; card documents label. Parser accepts one explicit alias and preserves original headers.",
              "split_relationships": overlap, "metadata_majority_rules_from_train": metadata_rules,
              "length_ranking_diagnostic": {"direction_selected_on_train": direction,
                                            "train_longer_dialogue_auc": train_auc,
                                            "test_auc_with_train_direction": test_auc,
                                            "threshold_selected": False},
              "not_checked": ["Semantic label validity", "Semantic near-duplicates or shared templates",
                              "Natural conversation fidelity", "Earliest evidence or warning-time annotations",
                              "Original generation prompts, model snapshots and sampling reproducibility",
                              "Real-world or Vietnamese transfer", "Any detector or engine quality"]}
    write_json(HERE / "aggregate.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
