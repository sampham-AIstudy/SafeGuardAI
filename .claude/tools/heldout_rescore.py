r"""Re-score the already-collected LLM results (checkpoint ~/.safeguard_heldout/results_v3_llm.json) with the CURRENT code,
WITHOUT calling any LLM: the stored final score of each llm_status=ok case is replayed as the LLM's risk through the real
orchestrator merge (so speech-act cap + hard-evidence logic run for real). Stored scores are max(tierA_old, llm), so for cases
where the LLM score was below Tier A the replayed value is an upper bound.
Usage: .venv\Scripts\python.exe .claude\tools\heldout_rescore.py [--set v3]"""
import json, os, sys, argparse
from collections import defaultdict
from pathlib import Path
from unittest.mock import patch
ap = argparse.ArgumentParser(); ap.add_argument("--set", default="v3"); a = ap.parse_args()
os.environ["SAFEGUARD_DB"] = "off"; os.environ["SAFEGUARD_NETWORK"] = "off"
for k in ("GROQ_API_KEY", "MISTRAL_API_KEY", "GEMINI_API_KEY", "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "GOOGLE_SAFE_BROWSING_KEY"):
    os.environ[k] = ""
sys.path.insert(0, os.getcwd())
from codebase.orchestrator import SafeGuardOrchestrator
from codebase.config import Settings
home = Path.home() / ".safeguard_heldout"
d = json.loads((home / f"heldout_{a.set}.json").read_text(encoding="utf-8"))
L = json.loads((home / f"results_{a.set}_llm.json").read_text(encoding="utf-8"))
txt = {i["id"]: i["t"] for i in d["scam"] + d["benign"]}
o = SafeGuardOrchestrator()
rows = []
for k, v in L.items():
    if v.get("llm_status") != "ok": continue
    fake = {"risk_score": v["score"], "explanation_breakdown": [], "recommendations": []}
    with patch("codebase.orchestrator.get_settings") as ms, patch.object(o.multi_llm_client, "is_active", True), \
         patch.object(o.multi_llm_client, "analyze_scam", return_value=fake):
        ms.return_value = Settings(offline=False, llm_mode="single", network_enabled=False, db_enabled=False)
        o.memory_agent.reset() if hasattr(o.memory_agent, "reset") else None
        r = o.process_request(txt[k], llm_mode="single", persist=False)
    capped = any(t.get("stage") == "speech_act_llm_cap" for t in r.get("pipeline_trace", []))
    rows.append((k, v["label"], v["kind"], v["score"], r["risk_score"], capped))
thr = lambda lab: 75 if lab == "S" else 40
kd = defaultdict(lambda: [0, 0, 0, 0])
for k, lab, kind, old, new, cap in rows:
    e = kd[("S:" if lab == "S" else "B:") + kind]; e[0] += 1; e[1] += old >= thr(lab); e[2] += new >= thr(lab); e[3] += cap
print(f"replayed {len(rows)} LLM-ok cases   [scam: HIGH+ ; benign: >=MEDIUM FP]   old_hybrid -> new_hybrid (cap applied)")
for key, (n, o_, n_, c) in sorted(kd.items()): print(f"  {key:<26} n={n:<2} {o_} -> {n_}  (cap {c})")
S = [r for r in rows if r[1] == "S"]; B = [r for r in rows if r[1] == "B"]
print(f"SCAM  n={len(S)}: HIGH+ old {sum(r[3]>=75 for r in S)} -> new {sum(r[4]>=75 for r in S)}")
print(f"BENIGN n={len(B)}: >=MED old {sum(r[3]>=40 for r in B)} -> new {sum(r[4]>=40 for r in B)} ; >=HIGH old {sum(r[3]>=75 for r in B)} -> new {sum(r[4]>=75 for r in B)}")
