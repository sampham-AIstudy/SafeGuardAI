"""Independent aggregate recounts and public-fixture checks; never print records."""
import ast
from collections import Counter
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import zipfile

from safeguard.evaluation.paths import ROOT as PROJECT, archive, output, private_output, inputs, release_input, local_artifact, QC, SCORER, save_json

HERE = output("capability")
ASSETS = archive("capability")
CODE = Path(__file__).resolve().parent
ROOT = PROJECT
csv.field_size_limit(10_000_000)
sha = lambda raw: hashlib.sha256(raw).hexdigest()
load = lambda name: json.loads((HERE / (name + ".json")).read_text())

spec = importlib.util.spec_from_file_location("audit", CODE / "analyze.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
execution = load("execution")
assert all(x["status"] == "complete" for x in execution.values())
lock = json.loads((ASSETS / "release-lock.json").read_text())
for name, entry in lock["files"].items():
    raw = release_input(entry["path"]).read_bytes()
    assert len(raw) == entry["bytes"] and sha(raw) == entry["sha256"], name
for name in execution:
    result = load(name)
    assert result["audit_script_sha256"] == sha((CODE / "analyze.py").read_bytes())
    assert result["release_lock_sha256"] == sha((ASSETS / "release-lock.json").read_bytes())
    for file, expected in result["source_sha256"].items():
        assert sha((ASSETS / "sources" / file).read_bytes()) == expected
print("PASS: all release bytes, final script/lock identities, and public method-source snapshots.")

for values in [[(1, 1), (0, 0)], [(1, 0), (0, 1)], [(1, 1), (1, 0)],
               [(0, 0), (1, 1), (2, 0), (2, 1), (3, 1)]]:
    pos = [s for s, y in values if y]
    neg = [s for s, y in values if not y]
    expected = sum((a > b) + .5 * (a == b) for a in pos for b in neg) / (len(pos) * len(neg))
    assert audit.auc(values) == expected
assert audit.auc([(1, 1)]) is None
roc_toy = [(0, 0), (1, 1), (2, 0), (3, 1)]
assert audit.auc(roc_toy) == audit.auc([p for p in roc_toy for _ in range(7 if p[1] == 0 else 1)]) == .75
try:
    audit.class_summary([{"text": "public toy", "label": "unexpected"}])
except ValueError:
    pass
else:
    raise AssertionError("Unexpected reference silently coerced")
assert audit.agreement([{"a": "1", "b": "1"}] * 2, "a", "b")["kappa"] is None
assert audit.confusion([1, 0], [1, 1])["fpr"] == 1
print("PASS: independent pairwise AUC fixtures, nonbinary-label regression, degenerate kappa and confusion counts.")

def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f, strict=True)
        header = next(reader)
        rows = list(reader)
    assert all(len(r) == len(header) for r in rows)
    return [dict(zip(header, r)) for r in rows]

base = inputs("phishvn")
originals = read_csv(base / "synthetic_sms.csv") + read_csv(base / "synthetic_email.csv")
index = {r["id"]: r for r in originals}
pv = load("phishvn")
assert Counter(r["label"] for r in originals) == {"phishing": 193, "benign": 143}
assert len(index) == len(originals) == pv["originals"]["rows"] == 336
assert all(r["split"] == "train" and all(ord(c) < 128 for c in r["text"]) for r in originals)
pos = [len(re.findall(r"\w+", r["text"])) for r in originals if r["label"] == "phishing"]
neg = [len(re.findall(r"\w+", r["text"])) for r in originals if r["label"] == "benign"]
assert sum((a > b) + .5 * (a == b) for a in pos for b in neg) / (len(pos) * len(neg)) == pv["originals"]["length_auc_longer_is_phishing"]
for file in ["paraphrase.csv", "paraphrase_band.csv"]:
    rows = read_csv(base / file)
    a = {r["src_id"] for r in rows if r["role"] == "train"}
    b = {r["src_id"] for r in rows if r["role"] == "test"}
    assert len(rows) == 386 and len(a & b) == 193
    assert all(r["src_id"] in index for r in rows)
    if file == "paraphrase_band.csv":
        for row in rows:
            tokens = lambda t: set(re.sub(r"https?://\S+", "", t.casefold()).split())
            a, b = tokens(index[row["src_id"]]["text"]), tokens(row["text"])
            similarity = len(a & b) / len(a | b)
            assert abs(similarity - float(row["jaccard"])) <= .000050001
ratings = read_csv(base / "human_eval_ratings.csv")
assert len(ratings) == 50
assert sum(r["meaning_preserved_A"] == r["meaning_preserved_B"] for r in ratings) == 49
assert sum(r["lure_intact_A"] == r["lure_intact_B"] for r in ratings) == 45
assert sum(r["more_persuasive_A"] == r["more_persuasive_B"] for r in ratings) == 16
assert sum(all(r[k] == "1" for k in ["meaning_preserved_A", "meaning_preserved_B", "lure_intact_A", "lure_intact_B"]) for r in ratings) == 44
print("PASS: PhishVN full recount, ASCII scope, all 27,599 length pairs, all rewrite links/Jaccard values, and human-review numerators.")

babi = load("babilong")
for task in ["qa1", "qa2", "qa3"]:
    for length in ["0k", "4k", "16k"]:
        rows = json.loads((inputs("babilong") / task / (length + ".json")).read_text())
        cell = babi["cells"][task + "/" + length]
        assert len(rows) == cell["rows"] == 100
        assert max(Counter(r["target"] for r in rows).values()) == cell["largest_target_count"]
        assert len({tuple(r[k] for k in ["input", "question", "target"]) for r in rows}) == 100
        vocabulary = {"bathroom", "bedroom", "garden", "hallway", "kitchen", "office"}
        hits = [[w for w in re.findall(r"\b\w+\b", r["input"].lower()) if w in vocabulary] for r in rows]
        assert sum(bool(h) and h[0] == r["target"] for r, h in zip(rows, hits)) / 100 == cell["first_location_rule_accuracy"]
        assert sum(bool(h) and h[-1] == r["target"] for r, h in zip(rows, hits)) / 100 == cell["last_location_rule_accuracy"]
        if length != "0k":
            short = json.loads((inputs("babilong") / task / "0k.json").read_text())
            verified = 0
            for a, b in zip(short, rows):
                cursor = 0
                ok = a["question"] == b["question"] and a["target"] == b["target"]
                for sentence in filter(None, map(str.strip, re.split(r"(?<=[.!?])\s+|\n+", a["input"]))):
                    location = b["input"].find(sentence, cursor)
                    if location < 0:
                        ok = False
                        break
                    cursor = location + len(sentence)
                verified += ok
            assert verified == babi["cross_length_story_pairing"][task + "/" + length]["same_row_question_target_and_ordered_story_sentences"]
assert babi["fixture_disagreements"] == 4
assert babi["cross_length_story_pairing"]["qa3/4k"]["same_row_question_and_target"] == 86
assert babi["cross_length_story_pairing"]["qa2/16k"]["suffix_coverage_diagnostic"]["1024"] == {
    "eligible_unique_story_matches": 92, "suffix_retains_all_short_story_sentences": 0}
print("PASS: all 900 BABILong records, class-prior references, cross-length audit results and declared scorer probes.")

with zipfile.ZipFile(inputs("phishrewrite") / "phishrewrite-benchmark-v1.0.zip") as z:
    assert z.testzip() is None
    emails = list(csv.DictReader(io.StringIO(z.read("data/emails.csv").decode(), newline="")))
    rewrites = list(csv.DictReader(io.StringIO(z.read("data/rewrites.csv").decode(), newline="")))
assert len(emails) == 28201 and len(rewrites) == 4000
idx = {r["original_id"]: r for r in emails}
assert all(idx[r["original_id"]]["split"] == "test" and idx[r["original_id"]]["label"] == "1" for r in rewrites)
pr = load("phishrewrite")
assert len({r["original_id"] for r in rewrites}) == pr["unique_parents_across_providers"] == 500
for provider in ["anthropic", "gemini"]:
    grouped = {}
    for r in rewrites:
        if r["provider"] == provider:
            grouped.setdefault(r["original_id"], []).append(r)
    count = sum(len(g) == 4 and all(r["retained_urls_strict"] == "True" and r["refused"] == "False" and r["rewrite_text"].strip() for r in g) for g in grouped.values())
    assert count == pr["providers"][provider]["all_severity_strict_intersection"]
# Execute only the already-inspected three pure checker functions and regex assignment,
# not imports, CLI, providers or generation code from the upstream attack module.
tree = ast.parse((ASSETS / "sources/phishrewrite_attack.py").read_text())
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"extract_urls", "_norm_url", "check_retention"}]
nodes += [n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "RETENTION_URL_RE" for t in n.targets)]
assert len(nodes) == 4
namespace = {"re": re}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "public_native_url_checker", "exec"), namespace)
refang = lambda t: t.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("www[.]", "www.")
for row in rewrites:
    actual = namespace["check_retention"](refang(idx[row["original_id"]]["text"]), refang(row["rewrite_text"]))["retained_urls"]
    expected = None if row["retained_urls_strict"] == "" else row["retained_urls_strict"] == "True"
    assert actual == expected
print("PASS: complete archive CRC, original/rewrite joins, native fixed-parent intersections and all 4,000 URL flags through actual native pure functions.")

icfd = load("icfd")
assert icfd["snapshot_files_checked"] == 55 and not icfd["snapshot_mismatches"]
ref = icfd["capability_reference_calculations"]
assert (ref["static/test"]["positive"], ref["static/test"]["negative"]) == (4477, 23)
assert (ref["streaming/test"]["positive"], ref["streaming/test"]["negative"]) == (115157, 64670)
assert ref["static/test"]["majority_exclusion_share"] == 1809 / 4476
print("PASS: unchanged 55-file ICFD audit snapshot and task-specific baseline/denominator calculations.")
print("No model, engine, generation or semantic relabeling was run. Passing audit checks do not validate unmeasured capability claims.")
