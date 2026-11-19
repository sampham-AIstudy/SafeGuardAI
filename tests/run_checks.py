"""Run component and handoff checks without access to benchmark files."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK_RUNS = ROOT / ".local" / "runs" / "checks"


class BenchmarkAccessError(PermissionError):
    pass


def source_hashes():
    paths = [p for directory in ("src", "tests") for p in (ROOT / directory).rglob("*")
             if p.is_file() and "__pycache__" not in p.parts and p.suffix in (".py", ".json", ".html", ".js")]
    paths.extend(ROOT / name for name in ("pyproject.toml", "pytest.ini"))
    paths.extend(ROOT / name for name in ("pixi.toml", "pixi.lock") if (ROOT / name).exists())
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def install_benchmark_guard():
    blocked = tuple(ROOT / name for name in
                    ("data/benchmarks", "data/development", "evaluation", "testset", "devset", ".audit-private"))
    attempts = []

    def guard(event, arguments):
        if event not in ("open", "os.listdir", "os.scandir", "os.mkdir") or not arguments:
            return
        path = arguments[0]
        if not isinstance(path, (str, bytes, os.PathLike)):
            return
        candidate = Path(os.fsdecode(path)).resolve()
        if any(candidate == base or base in candidate.parents for base in blocked):
            attempts.append(event)
            raise BenchmarkAccessError("Benchmark access is prohibited during development checks")

    sys.addaudithook(guard)
    for base in blocked:
        try:
            with (base / ".safeguard-guard-control").open("rb"):
                raise AssertionError("Benchmark guard did not reject the control")
        except BenchmarkAccessError:
            pass
    control_blocks = len(attempts)
    attempts.clear()
    return attempts, control_blocks


class CountingResult(unittest.TextTestResult):
    subcases = 0

    def addSubTest(self, test, subtest, error):
        self.subcases += 1
        super().addSubTest(test, subtest, error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    output = args.output_dir or CHECK_RUNS / datetime.now(timezone.utc).strftime("checks-%Y-%m-%dT%H%M%S.%fZ")
    attempts, control_blocks = install_benchmark_guard()
    output.mkdir(parents=True, exist_ok=False)
    sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
    before = source_hashes()

    with (output / "checks.log").open("x") as stream:
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py")
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=CountingResult).run(suite)
        contract_exit = 1
        previous_argv = sys.argv
        try:
            import contract_checks

            sys.argv = [str(ROOT / "tests/contract_checks.py"), "--out", str(output / "handoff-result.json")]
            contract_exit = contract_checks.main()
        except Exception:
            traceback.print_exc(file=stream)
        finally:
            sys.argv = previous_argv

    after = source_hashes()
    stable = before == after
    successful = result.testsRun > 0 and result.wasSuccessful() and contract_exit == 0 and stable and not attempts
    report = dict(successful=successful, tests_run=result.testsRun, subcases=result.subcases,
                  failures=len(result.failures), errors=len(result.errors),
                  handoff_exit_code=contract_exit, benchmark_access_guard_enabled=True,
                  guard_control_blocks=control_blocks, denied_benchmark_access_attempts=len(attempts),
                  source_unchanged_during_checks=stable, file_sha256=before, python=sys.version)
    if not stable:
        report["file_sha256_after_checks"] = after
    (output / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    summary = {key: value for key, value in report.items() if not key.startswith("file_sha256")}
    print(json.dumps(dict(output_dir=str(output), **summary), sort_keys=True))
    return int(not successful)


if __name__ == "__main__":
    raise SystemExit(main())
