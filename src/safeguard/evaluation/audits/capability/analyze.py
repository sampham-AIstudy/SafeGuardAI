"""Aggregate-only capability audit. No engine/model inference or semantic relabeling."""
from collections import Counter, defaultdict
import csv
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path
import re
import statistics
import unicodedata
import zipfile

from safeguard.evaluation.paths import ROOT as PROJECT, archive, output, private_output, inputs, release_input, local_artifact, QC, SCORER, save_json

HERE = archive("capability")
ROOT = PROJECT
OUT = output("capability")
csv.field_size_limit(10_000_000)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(name, obj):
    path = OUT / (name + ".json")
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(obj, indent=2) + "\n")
    tmp.replace(path)


def norm(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def words(text):
    return re.findall(r"\w+", text.casefold())


def describe(values):
    return {"count": len(values), "min": min(values), "median": statistics.median(values),
            "mean": statistics.mean(values), "max": max(values)} if values else None


def auc(values):
    grouped = defaultdict(Counter)
    for score, label in values:
        grouped[score][label] += 1
    p = sum(v[1] for v in grouped.values())
    n = sum(v[0] for v in grouped.values())
    if not p or not n:
        return None
    lower_n = 0
    wins = 0
    for score in sorted(grouped):
        c = grouped[score]
        wins += c[1] * (lower_n + .5 * c[0])
        lower_n += c[0]
    return wins / (p * n)


def confusion(rows, predictions):
    counts = Counter((label, pred) for label, pred in zip(rows, predictions))
    tp, fp, tn, fn = counts[1, 1], counts[0, 1], counts[0, 0], counts[1, 0]
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": (tp + tn) / len(rows), "recall": tp / (tp + fn) if tp + fn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "positive_f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "fpr": fp / (fp + tn) if fp + tn else None}


def csv_rows(raw):
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True)
    rows = list(reader)
    if any(None in r or any(v is None for v in r.values()) for r in rows):
        raise ValueError("Ragged CSV")
    return reader.fieldnames, rows


def class_summary(rows, text="text", label="label"):
    if any(r[label] not in {"0", "1", "phishing", "benign"} for r in rows):
        raise ValueError("Unexpected binary reference")
    y = [int(r[label]) if r[label] in ["0", "1"] else int(r[label] == "phishing") for r in rows]
    groups = defaultdict(set)
    for row, target in zip(rows, y):
        groups[norm(row[text])].add(target)
    return {"rows": len(rows), "labels": dict(Counter(y)),
            "empty_text": sum(not r[text].strip() for r in rows),
            "normalized_duplicate_excess": len(rows) - len(groups),
            "normalized_conflicting_groups": sum(len(v) > 1 for v in groups.values()),
            "words_by_label": {str(c): describe([len(words(r[text])) for r, t in zip(rows, y) if t == c]) for c in [0, 1]},
            "length_auc_longer_is_phishing": auc([(len(words(r[text])), t) for r, t in zip(rows, y)]),
            "always_positive": confusion(y, [1] * len(y)), "always_negative": confusion(y, [0] * len(y))}


def categorical_association(rows, field, label="label"):
    buckets = defaultdict(Counter)
    for row in rows:
        target = row[label] if row[label] in ["0", "1"] else str(int(row[label] == "phishing"))
        buckets[row[field]][target] += 1
    return {"groups": len(buckets), "pure_groups": sum(len(v) == 1 for v in buckets.values()),
            "oracle_group_majority_accuracy": sum(max(v.values()) for v in buckets.values()) / len(rows),
            "interpretation": "In-sample metadata association; not text-only performance"}


def agreement(rows, a, b):
    ca, cb = Counter(r[a] for r in rows), Counter(r[b] for r in rows)
    observed = sum(r[a] == r[b] for r in rows) / len(rows)
    expected = sum(ca[k] * cb[k] for k in ca.keys() | cb.keys()) / len(rows) ** 2
    return {"n": len(rows), "rater_a": dict(ca), "rater_b": dict(cb), "agreement": observed,
            "kappa": (observed - expected) / (1 - expected) if expected < 1 else None}


def phishvn():
    base = inputs("phishvn")
    loaded = {p.name: csv_rows(p.read_bytes()) for p in base.glob("*.csv")}
    originals = loaded["synthetic_sms.csv"][1] + loaded["synthetic_email.csv"][1]
    index = {r["id"]: r for r in originals}
    assert len(index) == len(originals)
    if any(r["label"] not in {"phishing", "benign"} for r in originals):
        raise ValueError("Unexpected PhishVN label")
    out = {"files": {k: {"columns": h, "rows": len(r)} for k, (h, r) in loaded.items()},
           "originals": class_summary(originals),
           "by_channel": {name: class_summary(loaded[name][1]) for name in ["synthetic_sms.csv", "synthetic_email.csv"]},
           "split_counts": dict(Counter(r["split"] for r in originals)),
           "metadata_associations": {k: categorical_association(originals, k) for k in ["gen_model", "scenario", "channel", "source", "label_source"]},
           "unique_original_url_field_values": len({r["url"] for r in originals}),
           "language_scope": {"lang_metadata": dict(Counter(r["lang"] for r in originals)),
               "original_rows_with_nonascii_text": sum(any(ord(c) > 127 for c in r["text"]) for r in originals),
               "interpretation": "ASCII-only texts do not test accented Vietnamese orthography; no semantic language validation is claimed"},
           "same_topic_controls": {s: dict(Counter(r["label"] for r in originals if r["scenario"] == s)) for s in sorted({r["scenario"] for r in originals})}}
    checksums = []
    for line in (base / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        path = base / name.lstrip("*")
        if path.exists():
            checksums.append(sha(path.read_bytes()) == expected)
    out["additional_sha256sum_checks"] = {"checked": len(checksums), "all_match": all(checksums)}
    rewrites = {}
    for name in ["paraphrase.csv", "paraphrase_band.csv"]:
        rows = loaded[name][1]
        linked = [r for r in rows if r["src_id"] in index]
        groups = defaultdict(list)
        for r in linked:
            groups[r["src_id"]].append(r)
        paired = []
        for r in linked:
            src = index[r["src_id"]]
            sa, sb = set(words(src["text"])), set(words(r["text"]))
            paired.append(len(sa & sb) / len(sa | sb) if sa | sb else 1)
        train_ids = {r["src_id"] for r in rows if r["role"] == "train"}
        test_ids = {r["src_id"] for r in rows if r["role"] == "test"}
        item = {"rows": len(rows), "linked_rows": len(linked), "unique_sources": len(groups),
                "variants_per_source": dict(Counter(len(g) for g in groups.values())),
                "role_counts": dict(Counter(r["role"] for r in rows)),
                "train_test_shared_source_ids": len(train_ids & test_ids),
                "test_rows_with_original_marked_train": sum(r["role"] == "test" and index[r["src_id"]]["split"] == "train" for r in linked),
                "source_label_disagreements": sum(r["label"] != index[r["src_id"]]["label"] for r in linked),
                "empty_rewrites": sum(not r["text"].strip() for r in rows),
                "rewrites_identical_to_source_normalized": sum(norm(r["text"]) == norm(index[r["src_id"]]["text"]) for r in linked),
                "normalized_unique_rewrite_texts": len({norm(r["text"]) for r in rows}),
                "recomputed_word_set_jaccard": describe(paired)}
        if "jaccard" in rows[0]:
            declared = [float(r["jaccard"]) for r in linked]
            item["declared_jaccard"] = describe(declared)
            item["declared_outside_band"] = sum(not .2 <= x <= .3 for x in declared)
            item["max_recomputed_difference"] = max(abs(a - b) for a, b in zip(paired, declared))
            reconstructed = []
            for r in linked:
                tokenize = lambda text: set(re.sub(r"https?://\S+", "", text.lower()).split())
                a, b = tokenize(index[r["src_id"]]["text"]), tokenize(r["text"])
                reconstructed.append(len(a & b) / len(a | b))
            item["url_removed_whitespace_jaccard"] = {
                "definition": "Lowercase, remove http(s) URLs, then set of whitespace-separated tokens",
                "values": describe(reconstructed),
                "match_declared_within_rounding": sum(abs(a - b) <= .000050001 for a, b in zip(reconstructed, declared)),
                "outside_band_with_rounding_tolerance": sum(not .19995 <= x <= .30005 for x in reconstructed)}
        rewrites[name] = item
    out["rewrites"] = rewrites
    ratings = loaded["human_eval_ratings.csv"][1]
    pairs = loaded["human_eval_pairs.csv"][1]
    rate_index = {r["pair_id"]: r for r in ratings}
    out["human_review"] = {
        "pairs": len(pairs), "ratings": len(ratings),
        "common_nonempty_field_conflicts": {k: sum(bool(p[k]) and p[k] != rate_index[p["pair_id"]][k] for p in pairs) for k in ratings[0] if k != "pair_id"},
        "pair_template_empty_rating_cells": sum(not p[k] for p in pairs for k in ratings[0] if k not in ["pair_id", "jaccard"]),
        "meaning": agreement(ratings, "meaning_preserved_A", "meaning_preserved_B"),
        "lure_intact": agreement(ratings, "lure_intact_A", "lure_intact_B"),
        "persuasion": agreement(ratings, "more_persuasive_A", "more_persuasive_B"),
        "both_raters_accept_meaning_and_lure": sum(all(r[k] == "1" for k in ["meaning_preserved_A", "meaning_preserved_B", "lure_intact_A", "lure_intact_B"]) for r in ratings),
        "reviewed_pair_texts_found_in_releases": sum(any(norm(p["rewrite"]) == norm(r["text"]) and norm(p["source"]) == norm(index[r["src_id"]]["text"]) for fn in ["paraphrase.csv", "paraphrase_band.csv"] for r in loaded[fn][1]) for p in pairs)}
    return out


def babilong():
    spec = importlib.util.spec_from_file_location("native_metrics", HERE / "sources/babilong_metrics.py")
    metrics = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(metrics)
    data = {}
    output = {}
    for task in ["qa1", "qa2", "qa3"]:
        labels = metrics.TASK_LABELS[task]
        for length in ["0k", "4k", "16k"]:
            rows = json.loads((inputs("babilong") / task / (length + ".json")).read_text())
            assert all(set(r) == {"input", "question", "target"} and all(isinstance(v, str) for v in r.values()) for r in rows)
            data[task, length] = rows
            first, last = [], []
            for r in rows:
                hits = [(m.start(), m.group().lower()) for m in re.finditer(r"\b(?:" + "|".join(labels) + r")\b", r["input"], re.I)]
                first.append(hits[0][1] if hits else "")
                last.append(hits[-1][1] if hits else "")
            targets = Counter(r["target"] for r in rows)
            output[task + "/" + length] = {
                "rows": len(rows), "empty_fields": {k: sum(not r[k].strip() for r in rows) for k in ["input", "question", "target"]},
                "distinct_targets": len(targets), "largest_target_count": max(targets.values()),
                "oracle_majority_target_accuracy": max(targets.values()) / len(rows),
                "uniform_task_label_expected_accuracy": 1 / len(labels),
                "duplicate_inputs": len(rows) - len({r["input"] for r in rows}),
                "duplicate_full_records": len(rows) - len({tuple(r[k] for k in ["input", "question", "target"]) for r in rows}),
                "input_word_count": describe([len(words(r["input"])) for r in rows]),
                "native_oracle_accuracy": sum(metrics.compare_answers(r["target"], r["target"], r["question"], labels) for r in rows) / len(rows),
                "first_location_rule_accuracy": sum(metrics.compare_answers(r["target"], p, r["question"], labels) for r, p in zip(rows, first)) / len(rows),
                "last_location_rule_accuracy": sum(metrics.compare_answers(r["target"], p, r["question"], labels) for r, p in zip(rows, last)) / len(rows)}
    pairing = {}
    for task in ["qa1", "qa2", "qa3"]:
        short = data[task, "0k"]
        for length in ["4k", "16k"]:
            longer = data[task, length]
            matches = []
            for r in longer:
                candidates = [s for s in short if s["question"] == r["question"] and s["target"] == r["target"]]
                found = []
                for s in candidates:
                    facts = [x.strip() for x in re.split(r"(?<=[.!?])\s+|\n+", s["input"]) if x.strip()]
                    cursor = 0
                    positions = []
                    for fact in facts:
                        pos = r["input"].find(fact, cursor)
                        if pos < 0:
                            break
                        positions.append(pos)
                        cursor = pos + len(fact)
                    if len(positions) == len(facts) and facts:
                        found.append((facts, positions))
                matches.append(found)
            window_results = {}
            for window in [128, 512, 1024]:
                eligible = kept_all = 0
                for r, found in zip(longer, matches):
                    if len(found) != 1:
                        continue
                    eligible += 1
                    suffix = " ".join(r["input"].split()[-window:])
                    kept_all += all(norm(f) in norm(suffix) for f in found[0][0])
                window_results[window] = {"eligible_unique_story_matches": eligible, "suffix_retains_all_short_story_sentences": kept_all}
            same_index_stories = 0
            for a, b in zip(short, longer):
                cursor = 0
                ok = a["question"] == b["question"] and a["target"] == b["target"]
                for fact in [x.strip() for x in re.split(r"(?<=[.!?])\s+|\n+", a["input"]) if x.strip()]:
                    pos = b["input"].find(fact, cursor)
                    if pos < 0:
                        ok = False
                        break
                    cursor = pos + len(fact)
                same_index_stories += ok
            pairing[task + "/" + length] = {
                "same_row_question_and_target": sum(a["question"] == b["question"] and a["target"] == b["target"] for a, b in zip(short, longer)),
                "same_row_question_target_and_ordered_story_sentences": same_index_stories,
                "ordered_short_story_match_count_distribution": dict(Counter(len(v) for v in matches)),
                "suffix_coverage_diagnostic": window_results,
                "interpretation": "All short-story sentences, not independently identified minimal supporting evidence; words, not model tokens"}
    fixtures = [("correct_single_label", "office", True), ("wrong_single_label", "garden", False),
                ("negated_target", "not office", False), ("substring_not_label", "officer", False),
                ("contradiction_after_period", "office. Actually garden.", False),
                ("abstention_with_target", "I cannot determine whether office is correct", False)]
    checks = [{"fixture": name, "intended": intended,
               "native": metrics.compare_answers("office", prediction, "Where is the item?", metrics.TASK_LABELS["qa1"])} for name, prediction, intended in fixtures]
    return {"cells": output, "cross_length_story_pairing": pairing,
            "public_scorer_fixtures": checks, "fixture_disagreements": sum(x["native"] != x["intended"] for x in checks),
            "scope": "900 bounded records, no model; lexical rules and parser probes are diagnostics"}


def phishrewrite():
    path = inputs("phishrewrite") / "phishrewrite-benchmark-v1.0.zip"
    with zipfile.ZipFile(path) as z:
        bad_crc = z.testzip()
        headers, emails = csv_rows(z.read("data/emails.csv"))
        rewrite_headers, rows = csv_rows(z.read("data/rewrites.csv"))
    by_id = {r["id"]: r for r in emails}
    if len(by_id) != len(emails):
        raise ValueError("Duplicate email ids")
    by_original = defaultdict(list)
    for r in emails:
        by_original[r["original_id"]].append(r)
    id_matches = sum(r["original_id"] in by_id for r in rows)
    original_matches = sum(r["original_id"] in by_original for r in rows)
    use_id = id_matches == len(rows)
    if not use_id and (original_matches != len(rows) or any(len(by_original[r["original_id"]]) != 1 for r in rows)):
        raise ValueError("Cannot establish unambiguous original/rewrite join")
    source = lambda r: by_id[r["original_id"]] if use_id else by_original[r["original_id"]][0]
    out = {"zip_crc_failure": bad_crc, "email_columns": headers, "rewrite_columns": rewrite_headers,
           "originals": class_summary(emails), "split_counts": dict(Counter(r["split"] for r in emails)),
           "by_split": {s: class_summary([r for r in emails if r["split"] == s]) for s in sorted({r["split"] for r in emails})},
           "metadata_source_association": categorical_association(emails, "source"),
           "rewrite_join": {"rows": len(rows), "matching_email_id": id_matches, "matching_source_original_id": original_matches,
                            "selected_join": "email.id" if use_id else "email.original_id", "parents_by_split_label": dict(Counter(source(r)["split"] + "/" + source(r)["label"] for r in rows))}}
    train = {norm(r["text"]) for r in emails if r["split"] == "train"}
    test = [r for r in emails if r["split"] == "test"]
    out["normalized_test_texts_seen_in_train"] = sum(norm(r["text"]) in train for r in test)
    groups = defaultdict(list)
    for r in rows:
        groups[r["provider"]].append(r)
    out["providers"] = {}
    true = lambda value: value.lower() == "true"
    for provider, provider_rows in groups.items():
        by_parent = defaultdict(list)
        cells = {}
        for r in provider_rows:
            by_parent[r["original_id"]].append(r)
        for severity in sorted({r["severity"] for r in provider_rows}, key=float):
            cell = [r for r in provider_rows if r["severity"] == severity]
            cells[severity] = {"rows": len(cell), "refused": sum(true(r["refused"]) for r in cell),
                              "empty_text": sum(not r["rewrite_text"].strip() for r in cell),
                              "strict_true": sum(true(r["retained_urls_strict"]) for r in cell),
                              "strict_false": sum(r["retained_urls_strict"].lower() == "false" for r in cell),
                              "strict_null": sum(r["retained_urls_strict"] == "" for r in cell),
                              "primary_true": sum(true(r["retained_urls_primary"]) for r in cell),
                              "normalized_identical_to_original": sum(norm(r["rewrite_text"]) == norm(source(r)["text"]) for r in cell)}
        out["providers"][provider] = {"rows": len(provider_rows), "parents": len(by_parent),
            "rows_per_parent": dict(Counter(len(g) for g in by_parent.values())), "severities": cells,
            "all_severity_strict_intersection": sum(len(g) == 4 and all(true(r["retained_urls_strict"]) and not true(r["refused"]) and r["rewrite_text"].strip() for r in g) for g in by_parent.values()),
            "all_severity_primary_intersection": sum(len(g) == 4 and all(true(r["retained_urls_primary"]) and not true(r["refused"]) and r["rewrite_text"].strip() for r in g) for g in by_parent.values())}
    out["unique_parents_across_providers"] = len({r["original_id"] for r in rows})
    # Exact URL retention diagnostic, independent of the author-supplied Boolean.
    def urls(text):
        text = text.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("www[.]", "www.")
        return set(re.findall(r"(?:https?://|www\.)[^\s<>\"']+", text, re.I))
    comparable = disagreements = 0
    for r in rows:
        original = urls(source(r)["text"])
        if original and r["retained_urls_strict"].lower() in {"true", "false"}:
            comparable += 1
            disagreements += (original <= urls(r["rewrite_text"])) != true(r["retained_urls_strict"])
    out["independent_lexical_url_check"] = {"comparable": comparable, "disagreements": disagreements,
        "interpretation": "Diagnostic regex; punctuation/extraction differences are not semantic label adjudications"}
    # Reconstruct the inspected pure native checker; never import the attack pipeline.
    retention_re = re.compile(r"""https?://[^\s<>"')\]]+|www\.[^\s<>"')\]]+""", re.I)
    def native_urls(text):
        text = text.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("www[.]", "www.")
        return list(dict.fromkeys(u.rstrip("/.,;:!?)]}>\"'").lower() for u in retention_re.findall(text)))
    def native_retained(a, b):
        orig, rw = native_urls(a), native_urls(b)
        if not orig:
            return None
        return all(u in rw or any(u in r or r in u for r in rw) for u in orig)
    native_disagreements = literal_mismatch_passes = 0
    for r in rows:
        a, b = source(r)["text"], r["rewrite_text"]
        result = native_retained(a, b)
        declared = None if not r["retained_urls_strict"] else true(r["retained_urls_strict"])
        native_disagreements += result != declared
        literal_mismatch_passes += result is True and not set(native_urls(a)) <= set(native_urls(b))
    fixture = [("same_url", "https://demo.example.test/login", "https://demo.example.test/login", True),
               ("different_url", "https://demo.example.test/login", "https://other.example.test/page", False),
               ("drop_path", "https://demo.example.test/login", "https://demo.example.test", False),
               ("change_host_by_suffix", "https://demo.example.test", "https://demo.example.test.attacker.test", False)]
    out["native_url_checker"] = {"declared_reproduction_disagreements": native_disagreements,
        "native_true_with_nonidentical_normalized_url_sets": literal_mismatch_passes,
        "public_fixtures": [{"name": name, "intended_identical_url": expected, "native": native_retained(a, b)} for name, a, b, expected in fixture],
        "interpretation": "URL substring matching is not destination or malicious-ask validation"}
    out["scoring_contract"] = {"paired_all_severity_intersection": True,
        "native_fixed_fpr_threshold_source": "Full test-ham score distribution; not a separate calibration split",
        "detector_scores_in_archive": False, "human_semantic_validity_labels_in_archive": False}
    return out


def icfd():
    base = archive("icfd")
    evidence = json.loads((base / "execution-evidence.json").read_text())
    mismatch = [name for name, expected in evidence["artifact_sha256"].items() if sha((base / name).read_bytes()) != expected]
    report = json.loads((output("icfd") / "data-audit.json").read_text())
    interpretation = json.loads((output("icfd") / "interpretation.json").read_text())
    references = {}
    for task in ["static", "streaming"]:
        for split in ["test", "cross_domain"]:
            labels = report["aggregate"][task][split]["labels"]
            p, n = labels["YES"], labels["NO"]
            selector = interpretation["native_majority_denominator_consequences"][split]
            references[task + "/" + split] = {"positive": p, "negative": n,
                "constant_yes_accuracy": p / (p + n), "constant_yes_positive_f1": 2 * p / (2 * p + n),
                "constant_yes_macro_f1": p / (2 * p + n), "constant_yes_balanced_accuracy": .5,
                "constant_yes_fpr": 1, "fpr_increment_percentage_points": 100 / n,
                "majority_excluded_source_scams_with_chunks": selector["source_fraud_not_majority_positive_chunks"],
                "majority_source_scams_with_chunks": selector["source_fraud_conversations"],
                "majority_exclusion_share": selector["source_fraud_not_majority_positive_chunks"] / selector["source_fraud_conversations"]}
    return {"snapshot_files_checked": len(evidence["artifact_sha256"]), "snapshot_mismatches": mismatch,
            "data_signature": evidence["data_signature"], "raw_data_signature": report["input_signature"],
            "existing_aggregate": report["aggregate"], "existing_interpretation": interpretation,
            "capability_reference_calculations": references,
            "scope": "Fresh raw-shard scan and reference calculations; unchanged historical source snapshot verified separately. No detector inference."}


def main():
    lock = json.loads((HERE / "release-lock.json").read_text())
    for name, entry in lock["files"].items():
        raw = release_input(entry["path"]).read_bytes()
        assert len(raw) == entry["bytes"] and sha(raw) == entry["sha256"], name
    results = {}
    for name, function in [("phishvn", phishvn), ("babilong", babilong), ("phishrewrite", phishrewrite), ("icfd", icfd)]:
        print("Starting " + name, flush=True)
        try:
            result = function()
            result["audit_script_sha256"] = sha(Path(__file__).read_bytes())
            result["release_lock_sha256"] = sha((HERE / "release-lock.json").read_bytes())
            result["source_sha256"] = {p.name: sha(p.read_bytes()) for p in sorted((HERE / "sources").glob("*")) if p.is_file()}
            save(name, result)
            results[name] = {"status": "complete", "artifact": name + ".json"}
        except Exception as exc:
            results[name] = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
        print(json.dumps({name: results[name]}), flush=True)
    save("execution", results)
    if any(r["status"] != "complete" for r in results.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
