"""Exercise the public check command with independently authored toy projects."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CheckRunnerTests(unittest.TestCase):
    def setUp(self):
        self.project = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.project / "tests").mkdir()
        (self.project / "src/safeguard/adapters").mkdir(parents=True)
        for name in ("tests/run_checks.py", "tests/contract_checks.py",
                     "src/safeguard/adapters/contract.schema.json", "pyproject.toml", "pytest.ini"):
            shutil.copy2(ROOT / name, self.project / name)
        (self.project / "tests/test_neutral.py").write_text(
            "import unittest\nclass NeutralTest(unittest.TestCase):\n"
            "    def test_addition(self):\n        self.assertEqual(2 + 2, 4)\n")

    def run_command(self, *options):
        return subprocess.run([sys.executable, "-I", "-B", str(self.project / "tests/run_checks.py"),
                               *options], capture_output=True, text=True, timeout=90)

    def test_success_records_component_contract_and_source_checks(self):
        runs = self.project / ".local/runs/checks"
        command = self.run_command()
        self.assertEqual(command.returncode, 0, command.stderr)
        (output,) = runs.iterdir()
        report = json.loads((output / "result.json").read_text())
        self.assertTrue(report["successful"])
        self.assertEqual(report["tests_run"], 1)
        self.assertEqual(report["guard_control_blocks"], 6)
        self.assertEqual(report["denied_benchmark_access_attempts"], 0)
        self.assertTrue(report["source_unchanged_during_checks"])
        self.assertEqual(json.loads((output / "handoff-result.json").read_text())["failed"], 0)
        self.assertIn("test_addition", (output / "checks.log").read_text())
        previous = (output / "result.json").read_bytes()
        self.assertNotEqual(self.run_command("--output-dir", str(output)).returncode, 0)
        self.assertEqual((output / "result.json").read_bytes(), previous)

    def test_source_symlink_is_blocked_before_any_target_bytes_are_read(self):
        target = self.project / "data/benchmarks/neutral-control.json"
        target.parent.mkdir(parents=True)
        target.write_text('{"independent_control":"newly authored toy content"}')
        (self.project / "tests/source-link.json").symlink_to(target)
        observer = """
import json
from pathlib import Path
import runpy
import sys
project = Path(sys.argv[1])
target = project / 'data/benchmarks/neutral-control.json'
completed = []
original = Path.read_bytes
def observe(path):
    data = original(path)
    if path.resolve() == target:
        completed.append(len(data))
    return data
Path.read_bytes = observe
sys.argv = [str(project / 'tests/run_checks.py'), '--output-dir', str(project / 'checks')]
try:
    runpy.run_path(sys.argv[0], run_name='__main__')
finally:
    (project / 'completed-reads.json').write_text(json.dumps(completed))
"""
        command = subprocess.run([sys.executable, "-I", "-B", "-c", observer, str(self.project)],
                                 capture_output=True, text=True, timeout=90)
        self.assertNotEqual(command.returncode, 0)
        self.assertIn("BenchmarkAccessError", command.stderr)
        self.assertEqual(json.loads((self.project / "completed-reads.json").read_text()), [])

    def test_blocked_output_directory_is_rejected_before_creation(self):
        for directory in ("data/benchmarks", "data/development", "devset"):
            with self.subTest(directory=directory):
                output = self.project / directory / "new-output"
                command = self.run_command("--output-dir", str(output))
                self.assertNotEqual(command.returncode, 0)
                self.assertIn("BenchmarkAccessError", command.stderr)
                self.assertFalse(output.exists())

    def test_source_identity_includes_environment_and_demo_assets(self):
        identities = {
            "pixi.toml": b'[workspace]\nname = "neutral-check-control"\n',
            "pixi.lock": b"version: 6\npackages: []\n",
            "src/safeguard/partner/ui/index.html": b"<!doctype html><title>Check fixture</title>\n",
            "src/safeguard/partner/ui/app.js": b"'use strict';\n",
        }
        for name, content in identities.items():
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        output = self.project / "checks"
        command = self.run_command("--output-dir", str(output))
        self.assertEqual(command.returncode, 0, command.stderr)
        manifest = json.loads((output / "result.json").read_text())["file_sha256"]
        for name, content in identities.items():
            self.assertEqual(manifest[name], hashlib.sha256(content).hexdigest())


if __name__ == "__main__":
    unittest.main()
