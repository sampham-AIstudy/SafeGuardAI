"""Resume the authorized CPU benchmark measurements in a fresh private run.

Run from the repository root: PYTHONPATH=src python3 -m safeguard.evaluation.remeasure
This is formal dataset measurement, never a development-test command or engine run.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from safeguard.evaluation.paths import ROOT, RUN, archive, output, save_json


def signature():
    files = sorted((ROOT / "src/safeguard/evaluation").rglob("*.py"))
    files += [archive("capability") / "release-lock.json", archive("icfd") / "release-lock.json",
              archive("bothbosu") / "release-lock.json"]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def main():
    RUN.mkdir(parents=True, exist_ok=True)
    manifest = RUN / "manifest.json"
    current = {"source_sha256": signature(), "scope": "CPU/data/scoring remeasurement; no model inference"}
    if manifest.exists():
        if json.loads(manifest.read_text()) != current:
            raise RuntimeError("Run inputs changed; select a fresh SAFEGUARD_AUDIT_RUN")
    else:
        save_json(manifest, current)
    lock = output("bothbosu") / "release-lock.json"
    if not lock.exists():
        shutil.copyfile(archive("bothbosu") / "release-lock.json", lock)
    pinned_python = archive("icfd") / ".pixi/envs/default/bin/python"
    if not pinned_python.exists():
        raise RuntimeError("The pinned ICFD parser environment is unavailable")
    env = dict(os.environ, PYTHONPATH=str(ROOT/"src"), PYTHONUNBUFFERED="1")
    prefix = "safeguard.evaluation.audits."
    stages = [
        ("icfd-scan", [str(pinned_python), "-m", prefix+"icfd.scan"], 1800),
        ("icfd-analyze", [str(pinned_python), "-m", prefix+"icfd.analyze"], 180),
        ("capability-analyze", [sys.executable, "-m", prefix+"capability.analyze"], 240),
        ("capability-verify", [sys.executable, "-m", prefix+"capability.verify"], 120),
        ("bothbosu-audit", [sys.executable, "-m", prefix+"bothbosu.audit", "--data-dir", str(ROOT/"data/benchmarks/bothbosu")], 180),
        ("bothbosu-verify", [sys.executable, "-m", prefix+"bothbosu.verify"], 60),
        ("local-audit", [sys.executable, "-m", prefix+"local.audit"], 90),
        ("local-verify", [sys.executable, "-m", prefix+"local.verify"], 90),
    ]
    state_path = RUN / "stages.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    for name, command, deadline in stages:
        if state.get(name, {}).get("status") == "complete":
            print("Reusing completed stage: " + name, flush=True)
            continue
        log = RUN / (name + ".log")
        started = time.monotonic()
        state[name] = {"status": "running", "command": command, "operational_timeout_seconds": deadline}
        save_json(state_path, state)
        print("Starting " + name, flush=True)
        with log.open("w") as stream:
            try:
                result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=deadline)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
        if name == "bothbosu-audit" and code == 0:
            shutil.copyfile(log, output("bothbosu") / "execution.log")
        state[name].update(status="complete" if code == 0 else "failed", exit_code=code,
                           elapsed_seconds=time.monotonic()-started,
                           log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
        save_json(state_path, state)
        print(name + ": " + state[name]["status"], flush=True)
        if code:
            # Raw logs stay private. Do not print exception messages or case data.
            raise SystemExit(code)
    print("All authorized audit stages complete. Outputs require aggregate comparison and log review.", flush=True)


if __name__ == "__main__":
    main()
