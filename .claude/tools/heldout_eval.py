r"""Score the offline pipeline on the private held-out set (stored OUTSIDE the repo, never shown to agy).
Usage: .venv\Scripts\python.exe .claude\tools\heldout_eval.py [--list]
Prints recall HIGH+, recall >=MEDIUM, FPR >=MEDIUM / >=HIGH; --list prints wrong ids only (not texts)."""
import json, os, sys
os.environ["SAFEGUARD_OFFLINE"] = "1"
sys.path.insert(0, os.getcwd())
from pathlib import Path
from codebase.orchestrator import SafeGuardOrchestrator

name = "heldout_urls_v1.json" if "--urls" in sys.argv else ("heldout_v3.json" if "--v3" in sys.argv else ("heldout_v2.json" if "--v2" in sys.argv else "heldout_v1.json"))
p = Path.home() / ".safeguard_heldout" / name
d = json.loads(p.read_text(encoding="utf-8"))
o = SafeGuardOrchestrator()
def score(t):
    o.memory_agent.reset() if hasattr(o.memory_agent, "reset") else None
    r = o.process_request(t, persist=False)
    return r.get("risk_score") or 0
s = {i["id"]: score(i["t"]) for i in d["scam"]}
b = {i["id"]: score(i["t"]) for i in d["benign"]}
n, m = len(s), len(b)
hi = sum(v >= 75 for v in s.values()); med = sum(v >= 40 for v in s.values())
fm = sum(v >= 40 for v in b.values()); fh = sum(v >= 75 for v in b.values())
print(f"scam n={n}: recall HIGH+ {hi}/{n} ({hi/n:.0%}), >=MEDIUM {med}/{n} ({med/n:.0%})")
print(f"benign n={m}: FPR >=MEDIUM {fm}/{m} ({fm/m:.0%}), >=HIGH {fh}/{m} ({fh/m:.0%})")
if "--list" in sys.argv:
    print("scam <75:", {k: v for k, v in s.items() if v < 75})
    print("benign >=40:", {k: v for k, v in b.items() if v >= 40})
if "--kinds" in sys.argv:
    from collections import defaultdict
    kd = defaultdict(lambda: [0, 0])
    for i in d["scam"]:
        kd["S:" + i.get("kind", "?")][1] += 1; kd["S:" + i.get("kind", "?")][0] += s[i["id"]] >= 75
    for i in d["benign"]:
        kd["B:" + i.get("kind", "?")][1] += 1; kd["B:" + i.get("kind", "?")][0] += b[i["id"]] >= 40
    for k, (x, y) in sorted(kd.items()): print(f"  {k}: {x}/{y}" + ("  (scam HIGH+)" if k[0] == "S" else "  (benign FP>=MED)"))
