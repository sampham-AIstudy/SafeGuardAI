"""Compact verification: pytest + offline evals (v1, v2, v2-dev, v2-test) in ONE short report.

Usage:  .venv\\Scripts\\python.exe .claude\\tools\\verify.py [--save] [--no-pytest]
  --save       store this run as the new baseline (.claude/handoffs/last_metrics.json)
  --no-pytest  skip pytest
Writes eval JSON to a temp dir (never to eval/results). Prints <40 lines, including the
list of golden cases whose predicted label changed since the last saved baseline.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / ".claude" / "handoffs" / "last_metrics.json"
V2 = str(ROOT / "eval" / "golden_set_v2.json")
RUNS = [
    ("v1", []),
    ("v2", ["--set", V2]),
    ("dev", ["--set", V2, "--split", "dev"]),
    ("test", ["--set", V2, "--split", "test"]),
]
RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def run(cmd):
    env = dict(os.environ, PYTHONIOENCODING="utf-8", SAFEGUARD_OFFLINE="1")
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env)


def pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


def main():
    save = "--save" in sys.argv
    t0 = time.time()
    if "--no-pytest" not in sys.argv:
        p = run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"])
        lines = [l for l in p.stdout.splitlines() if l.strip()]
        print("pytest:", lines[-1] if lines else "(no output)")
        for l in lines:
            if l.startswith(("FAILED", "ERROR")):
                print("  ", l[:160])
    last = json.loads(BASE.read_text(encoding="utf-8")) if BASE.exists() else {}
    snap, changes = {}, []
    print(f"{'set':5} {'n':>3} {'exact':>6} {'lenient':>7} {'F1':>5} {'critS':>6} {'FPR':>6} {'HIGH+R':>6} {'p95ms':>6}")
    with tempfile.TemporaryDirectory() as tmp:
        for name, extra in RUNS:
            out = Path(tmp) / f"{name}.json"
            p = run([sys.executable, "eval/run_eval.py", "--mode", "offline", "--no-sleep",
                     "--out", str(out), *extra])
            if not out.exists():
                print(f"{name:5} FAILED to run: {(p.stderr or p.stdout)[-200:]}")
                continue
            d = json.loads(out.read_text(encoding="utf-8"))
            m = d["metrics"]
            hp = (m.get("binary_high_plus") or {}).get("recall")
            p95 = (m.get("latency") or {}).get("p95_ms")
            print(f"{name:5} {m['total_cases']:>3} {pct(m['accuracy_exact']):>6} "
                  f"{pct(m['accuracy_lenient']):>7} {m['macro_f1']:.2f} "
                  f"{pct(m['critical_recall_strict']):>6} {pct(m['fpr_benign']):>6} "
                  f"{pct(hp):>6} {p95 if p95 is not None else 'n/a':>6}")
            snap[name] = {r["id"]: [r["predicted_risk_level"], r["risk_score"], r["expected_risk_level"]]
                          for r in d["results"]}
            if name in ("v1", "v2"):  # dev/test are subsets of v2
                for cid, (pred, sc, exp) in snap[name].items():
                    old = (last.get(name) or {}).get(cid)
                    if old and old[0] != pred:
                        was_ok, now_ok = old[0] == exp, pred == exp
                        tag = "BETTER" if now_ok and not was_ok else "WORSE" if was_ok and not now_ok else "moved"
                        changes.append(f"  {name}/{cid} {old[0]}({old[1]})->{pred}({sc}) exp={exp} [{tag}]")
    if changes:
        print(f"changed vs baseline ({len(changes)}):")
        print("\n".join(sorted(changes)[:30]))
    elif last:
        print("no per-case label changes vs baseline")
    else:
        print("(no baseline saved yet; use --save)")
    if save:
        BASE.write_text(json.dumps(snap, ensure_ascii=False), encoding="utf-8")
        print(f"baseline saved -> {BASE.relative_to(ROOT)}")
    st = run(["git", "status", "--short"]).stdout.splitlines()
    ignore = (".claude/", ".gitnexusignore", "AGENTS.md", "CLAUDE.md")
    st = [l for l in st if not any(i in l for i in ignore)]
    print(f"git: {len(st)} changed/new paths (excluding tooling); took {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
