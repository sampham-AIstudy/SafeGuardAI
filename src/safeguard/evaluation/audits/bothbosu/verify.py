"""Cross-check the saved audit with independent parsing and public fixtures."""

from collections import Counter
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import statistics
import tempfile
import unicodedata


from safeguard.evaluation.paths import ROOT as PROJECT, archive, output, private_output, inputs, release_input, local_artifact, QC, SCORER, save_json

HERE = output("bothbosu")
CODE = Path(__file__).resolve().parent
ROOT = PROJECT
DATA = inputs("bothbosu")
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

report = json.loads((HERE / "aggregate.json").read_text())
lock = json.loads((HERE / "release-lock.json").read_text())
assert sha(CODE / "audit.py") == report["script_sha256"]
assert sha(HERE / "release-lock.json") == report["input_lock_sha256"]
for name, entry in lock["files"].items():
    path = DATA / name
    assert path.stat().st_size == entry["bytes"] and sha(path) == entry["sha256"]
print("PASS: script, lock and all four downloaded file identities.")

rows = {}
for split in ["all", "train", "test"]:
    with (DATA / f"agent_conversation_{split}.csv").open(encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f, strict=True)
        assert next(reader) == ["dialogue", "personality", "type", "labels"]
        data = list(reader)
    assert all(len(r) == 4 and r[3] in ["0", "1"] and all(c.strip() for c in r) for r in data)
    rows[split] = data
    measured = report["splits"][split]
    assert len(data) == measured["rows"]
    assert Counter(r[3] for r in data) == Counter(measured["labels"])
    for label in ["0", "1"]:
        counts = [len(re.findall(r"\w+", r[0])) for r in data if r[3] == label]
        assert statistics.median(counts) == measured["word_count_by_label"][label]["median"]
        assert statistics.mean(counts) == measured["word_count_by_label"][label]["mean"]
print("PASS: independent CSV-reader recount of all 3,200 file rows and per-class length statistics.")

assert Counter(map(tuple, rows["all"])) == Counter(map(tuple, rows["train"])) + Counter(map(tuple, rows["test"]))
normalize = lambda text: " ".join(unicodedata.normalize("NFKC", text).casefold().split())
for normalize_text in [lambda text: text, normalize]:
    assert not {normalize_text(r[0]) for r in rows["train"]} & {normalize_text(r[0]) for r in rows["test"]}
    assert len({normalize_text(r[0]) for r in rows["all"]}) == 1600
positive = [len(re.findall(r"\w+", r[0])) for r in rows["test"] if r[3] == "1"]
negative = [len(re.findall(r"\w+", r[0])) for r in rows["test"] if r[3] == "0"]
pair_auc = sum((a > b) + .5 * (a == b) for a in positive for b in negative) / (len(positive) * len(negative))
assert pair_auc == report["length_ranking_diagnostic"]["test_auc_with_train_direction"] == .7845703125
print("PASS: split separation, multiset identity and test length AUC from all 25,600 pairs.")

spec = importlib.util.spec_from_file_location("audit", CODE / "audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
for toy in [[(1, 1), (0, 0)], [(1, 0), (0, 1)], [(1, 0), (1, 1)], [(0, 0), (1, 1), (2, 0), (2, 1), (3, 1)]]:
    pos = [s for s, y in toy if y]
    neg = [s for s, y in toy if not y]
    assert audit.auc(toy) == sum((a > b) + .5 * (a == b) for a in pos for b in neg) / (len(pos) * len(neg))
assert audit.auc([(1, 1)]) is None
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / "public.csv"
    for label_column in ["label", "labels"]:
        path.write_text(f'dialogue,personality,type,{label_column}\n"toy first line\nsecond line",polite,support,1\n"toy legitimate, call",polite,delivery,0\n')
        header, parsed = audit.read_csv(path)
        assert len(parsed) == 2 and parsed[0]["label"] == "1" and "\n" in parsed[0]["dialogue"]
        assert audit.row_keys(parsed + parsed, "row").total() == 4
        assert len(audit.row_keys(parsed + parsed, "row")) == 2
    for invalid in ["dialogue,personality,type,label,labels\ntoy,polite,support,1,0\n",
                    "dialogue,personality,type,labels\ntoy,polite,support,2\n",
                    "dialogue,personality,type,labels\ntoy,polite,support,1,extra\n"]:
        path.write_text(invalid)
        try:
            audit.read_csv(path)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid public fixture accepted")
print("PASS: public AUC, schema-alias regression, multiline CSV, duplicate, invalid-label and ragged-row fixtures.")

log = (HERE / "execution.log").read_text()
assert "Traceback" not in log and json.loads(log) == report
catalog = ROOT / "evaluation/BENCHMARKS.md"
for target in re.findall(r"\]\(([^)]+)\)", catalog.read_text()):
    if "://" not in target and not target.startswith("#"):
        assert (catalog.parent / target.split("#")[0]).exists(), target
assert "| BothBosu conversation dataset audit | IN PROGRESS" not in (ROOT / "STATUS.md").read_text()
print("PASS: complete final execution log, local catalog links and current audit status.")
print("Resolved checks: singular-label parser assumption; independent check initially omitted the all-file UTF-8 BOM. Final parser and cross-check handle both.")
print("Scope: aggregate CPU/data checks, not semantic validity or detector performance.")
