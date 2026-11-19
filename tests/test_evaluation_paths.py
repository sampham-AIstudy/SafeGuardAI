"""Toy path checks only; no benchmark files, labels or content are read."""

from pathlib import Path
import unittest

from safeguard.evaluation import paths


class EvaluationPathTests(unittest.TestCase):
    def test_current_project_root(self):
        self.assertEqual(paths.ROOT, Path(__file__).resolve().parents[1])

    def test_archive_location(self):
        self.assertEqual(paths.archive("local"), paths.ROOT / "evaluation/audits/local-suitability-audit-2026-11-08")

    def test_historical_release_name_maps_to_canonical_root(self):
        result = paths.release_input(".audit-private/capability-audit-2026-11-07/babilong/toy.json")
        self.assertEqual(result, paths.ROOT / "data/benchmarks/babilong/toy.json")

    def test_qc_mapping_without_link(self):
        self.assertEqual(paths.local_artifact("qc/toy.json"), paths.QC / "toy.json")
        self.assertEqual(paths.local_artifact("toy.json"), paths.inputs("SGC-250") / "synthetic-v1/toy.json")

    def test_release_source_file_is_not_treated_as_dataset_input(self):
        value = paths.release_input("evaluation/capability-audit-2026-11-07/sources/toy.py")
        self.assertEqual(value, paths.archive("capability") / "sources/toy.py")

    def test_unknown_release_prefix_is_rejected(self):
        with self.assertRaises(ValueError):
            paths.release_input("unknown/toy.json")

    def test_path_traversal_is_rejected(self):
        for relative in ["../toy.json", "/toy.json", "inside/../../toy.json"]:
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                paths.safe_join(Path("toy-root"), relative)


if __name__ == "__main__":
    unittest.main()
