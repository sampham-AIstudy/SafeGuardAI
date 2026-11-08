"""Scorer tests on public toy chats only; never load the held-out dataset."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("score.py")
SPEC = importlib.util.spec_from_file_location("scorer", SCRIPT)
SCORER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCORER)


def toy_run():
    records = []
    warnings = [2, 4, 1, None, None, 0]
    for i, label in enumerate(["scam"] * 4 + ["benign"] * 2):
        records.append({"id": "public-toy-" + str(i),
                        "input": {"messages": [{"text": "PUBLIC_TOY_CONTENT"}] * 5},
                        "gold": {"label": label, "alert_turn": 2 if label == "scam" else None}})
    for a, b in [(0, 4), (2, 5)]:
        records[a]["gold"]["paired_with"] = records[b]["id"]
        records[b]["gold"]["paired_with"] = records[a]["id"]
    return records, [{"id": r["id"], "first_warning": w} for r, w in zip(records, warnings)]


class ScoringTests(unittest.TestCase):
    def test_known_precision_timing_and_pairs(self):
        records, predictions = toy_run()
        result = SCORER.score(records, predictions)
        self.assertEqual(result["status"], "complete")
        m = result["metrics"]
        for key in ("conversation_precision", "conversation_recall", "conversation_f1"):
            self.assertEqual(m[key], 0.75)
        self.assertEqual(m["benign_false_alarm_rate"], 0.5)
        self.assertEqual(m["premature_warning_rate"], 0.25)
        self.assertEqual(m["miss_rate"], 0.25)
        self.assertEqual(m["evidence_respecting_detection_rate"], 0.5)
        self.assertEqual(m["exact_boundary_detection_rate"], 0.25)
        self.assertEqual(m["warning_delay_mean_messages"], 1)
        self.assertEqual(m["warning_delay_median_messages"], 1)
        self.assertEqual(m["warning_delay_denominator"], 2)
        self.assertEqual(m["paired_near_miss_success_rate"], 0.5)

    def test_zero_warning_index_and_no_warning_are_distinct(self):
        records, predictions = toy_run()
        records[0]["gold"]["alert_turn"] = 0
        predictions[0]["first_warning"] = 0
        result = SCORER.score(records, predictions)
        self.assertEqual(result["observed_counts"]["exact_boundary_scam"], 1)
        self.assertEqual(result["observed_counts"]["missed_scam"], 1)

    def test_no_detections_have_null_delay_not_zero(self):
        records, predictions = toy_run()
        for row in predictions:
            row["first_warning"] = None
        m = SCORER.score(records, predictions)["metrics"]
        self.assertIsNone(m["conversation_precision"])
        self.assertEqual(m["conversation_f1"], 0)
        self.assertEqual(m["miss_rate"], 1)
        self.assertIsNone(m["warning_delay_mean_messages"])
        self.assertEqual(m["warning_delay_denominator"], 0)

    def test_failures_never_silently_become_negative_predictions(self):
        records, predictions = toy_run()
        predictions[-1].update(first_warning=None, status="error")
        result = SCORER.score(records, predictions[:-2] + predictions[-1:])
        self.assertIsNone(result["metrics"])
        self.assertEqual(result["problems"]["execution_errors"], 1)
        self.assertEqual(result["problems"]["missing_ids"], 1)
        self.assertEqual(result["unscored_by_label"], {"benign": 2})

    def test_duplicates_unknown_and_malformed_are_reported(self):
        records, predictions = toy_run()
        predictions += [copy.deepcopy(predictions[0]), {"id": "unknown", "first_warning": None}, None]
        result = SCORER.score(records, predictions)
        self.assertIsNone(result["metrics"])
        self.assertEqual(result["problems"]["duplicate_ids"], 1)
        self.assertEqual(result["problems"]["unknown_id_rows"], 1)
        self.assertEqual(result["problems"]["malformed_rows"], 1)

    def test_bad_warning_types_and_indices_are_rejected(self):
        records, base = toy_run()
        for warning in [True, -1, 5, "2", 1.0]:
            with self.subTest(warning=warning):
                predictions = copy.deepcopy(base)
                predictions[0]["first_warning"] = warning
                result = SCORER.score(records, predictions)
                self.assertIsNone(result["metrics"])
                self.assertEqual(result["problems"]["malformed_rows"], 1)

    def test_bad_pairing_is_dataset_error(self):
        records, predictions = toy_run()
        del records[4]["gold"]["paired_with"]
        with self.assertRaisesRegex(ValueError, "pairing"):
            SCORER.score(records, predictions)

    def test_resource_totals_expose_missing_accounting(self):
        records, predictions = toy_run()
        predictions[0]["resources"] = {"tokens": 10, "elapsed_seconds": 1.5}
        predictions[1]["resources"] = {"tokens": 30, "model_calls": 2}
        resources = SCORER.score(records, predictions)["resources"]
        self.assertEqual(resources["tokens"], {"reported_conversations": 2, "total": 40, "mean": 20})
        self.assertEqual(resources["model_calls"]["reported_conversations"], 1)
        self.assertIsNone(resources["tool_calls"]["total"])
        predictions[0]["resources"]["elapsed_seconds"] = float("nan")
        self.assertIsNone(SCORER.score(records, predictions)["metrics"])


class CommandTests(unittest.TestCase):
    def test_cli_identity_guards_and_aggregate_only_output(self):
        records, predictions = toy_run()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data, pred, manifest, run, out = [root / name for name in
                                              ["data.jsonl", "pred.jsonl", "manifest.json", "run.json", "aggregate.json"]]
            data.write_text("".join(json.dumps(r) + "\n" for r in records))
            pred.write_text("".join(json.dumps(r) + "\n" for r in predictions))
            meta = {"status": "frozen", "testset_version": "public-toy",
                    "conversations_sha256": hashlib.sha256(data.read_bytes()).hexdigest()}
            run_meta = {"testset_version": "public-toy", "dataset_sha256": meta["conversations_sha256"],
                        "predictions_sha256": hashlib.sha256(pred.read_bytes()).hexdigest()}
            manifest.write_text(json.dumps(meta))
            run.write_text(json.dumps(run_meta))
            protocol = root / "BENCHMARK_PROTOCOL.md"
            protocol.write_text("PUBLIC_TOY_PROTOCOL")
            meta.update(protocol_version="1.0", protocol_path=protocol.name,
                        protocol_sha256=hashlib.sha256(protocol.read_bytes()).hexdigest())
            manifest.write_text(json.dumps(meta))
            command = [sys.executable, "-I", str(SCRIPT), "--data", str(data), "--predictions", str(pred),
                       "--manifest", str(manifest), "--run-manifest", str(run), "--out", str(out)]
            def invoke():
                result = subprocess.run(command, text=True, capture_output=True, timeout=10)
                self.assertNotIn("PUBLIC_TOY_CONTENT", result.stdout + result.stderr)
                self.assertNotIn("public-toy-0", result.stdout + result.stderr)
                return result
            result = invoke()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(out.read_text())["metrics"]["conversation_f1"], 0.75)
            protocol.write_text("CHANGED_PUBLIC_TOY_PROTOCOL")
            self.assertEqual(invoke().returncode, 2)
            protocol.write_text("PUBLIC_TOY_PROTOCOL")
            meta["status"] = "provisional"
            manifest.write_text(json.dumps(meta))
            self.assertEqual(invoke().returncode, 2)
            meta["status"] = "frozen"
            meta["conversations_sha256"] = "wrong"
            manifest.write_text(json.dumps(meta))
            self.assertEqual(invoke().returncode, 2)
            meta["conversations_sha256"] = run_meta["dataset_sha256"]
            manifest.write_text(json.dumps(meta))
            run_meta["predictions_sha256"] = "wrong"
            run.write_text(json.dumps(run_meta))
            self.assertEqual(invoke().returncode, 2)
            pred.write_text(pred.read_text() + "malformed JSON\n")
            run_meta["predictions_sha256"] = hashlib.sha256(pred.read_bytes()).hexdigest()
            run.write_text(json.dumps(run_meta))
            self.assertEqual(invoke().returncode, 1)
            self.assertIsNone(json.loads(out.read_text())["metrics"])


if __name__ == "__main__":
    unittest.main()
