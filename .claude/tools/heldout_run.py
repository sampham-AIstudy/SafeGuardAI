r"""Run the pipeline on a private held-out set and save per-id scores (NO texts) outside the repo.
Usage: .venv\Scripts\python.exe .claude\tools\heldout_run.py --set v3 --mode offline|llm [--stratified]
         [--models m1,m2,...] [--max-new N] [--limit N] [--pace S]
llm mode: Gemini single only (other provider keys blanked), network OFF, DB OFF, online_check False.
  --stratified : round-robin over scenario kinds, hard-FP benign + weak scam kinds first (so a small daily quota
                 still covers every kind); otherwise file order.
  --models     : Gemini models tried in order; after 3 consecutive LLM failures the next model is used
                 (each model has its own free-tier daily quota). Per-case model is recorded.
  --max-new N  : stop after N NEW successful LLM answers this run (protect quota).
Results are checkpointed after every case; cases already llm_status=ok are never re-run.
Output: ~/.safeguard_heldout/results_<set>_<mode>.json"""
import argparse, json, os, sys, time
from collections import defaultdict
ap = argparse.ArgumentParser()
ap.add_argument("--set", default="v3"); ap.add_argument("--mode", default="offline")
ap.add_argument("--models", default="gemini-2.5-flash,gemini-3-flash-preview,gemini-3.5-flash-lite")
ap.add_argument("--stratified", action="store_true"); ap.add_argument("--max-new", type=int, default=0)
ap.add_argument("--limit", type=int, default=0); ap.add_argument("--pace", type=float, default=0.0)
a = ap.parse_args()
models = [m.strip() for m in a.models.split(",") if m.strip()]
os.environ["SAFEGUARD_DB"] = "off"
if a.mode == "offline":
    os.environ["SAFEGUARD_OFFLINE"] = "1"
else:
    os.environ.pop("SAFEGUARD_OFFLINE", None)
    os.environ["SAFEGUARD_NETWORK"] = "off"; os.environ["SAFEGUARD_LLM_MODE"] = "single"
    os.environ["SAFEGUARD_LLM_TIMEOUT"] = "45"   # slow models (e.g. 3.5-flash-lite ~18s) are accepted for benchmark runs
    # ONLY Gemini is authorised to see the synthetic texts: blank every other provider/TI key (load_dotenv does not override existing vars)
    for k in ("GROQ_API_KEY", "MISTRAL_API_KEY", "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "GOOGLE_SAFE_BROWSING_KEY"):
        os.environ[k] = ""
sys.path.insert(0, os.getcwd())
from pathlib import Path
from codebase.orchestrator import SafeGuardOrchestrator
home = Path.home() / ".safeguard_heldout"
d = json.loads((home / f"heldout_{a.set}.json").read_text(encoding="utf-8"))
out_p = home / f"results_{a.set}_{a.mode}.json"
res = json.loads(out_p.read_text(encoding="utf-8")) if out_p.exists() else {}

def make_orc(model):
    if a.mode == "llm":
        os.environ["GEMINI_MODEL"] = model
    o = SafeGuardOrchestrator()
    if a.mode == "llm" and hasattr(o, "multi_llm_client"):
        o.multi_llm_client.PROVIDER_TIMEOUT = 40
    return o

PRIORITY_B = ["news_report_scam", "police_bank_warning", "victim_asks_advice", "everyday_money_chat", "user_asks_prevention", "real_otp_balance"]
PRIORITY_S = ["job_task", "romance", "hacked_friend_borrow", "delivery_customs", "investment", "deepfake_call", "tech_support_remote"]
items = [("S", i) for i in d["scam"]] + [("B", i) for i in d["benign"]]
if a.limit: items = items[: a.limit // 2] + items[len(d["scam"]): len(d["scam"]) + a.limit // 2]
if a.stratified:
    groups = defaultdict(list)
    for lab, it in items: groups[(lab, it.get("kind"))].append((lab, it))
    def rank(k):
        lab, kind = k
        if lab == "B": return (0, PRIORITY_B.index(kind)) if kind in PRIORITY_B else (3, 0)
        return (1, PRIORITY_S.index(kind)) if kind in PRIORITY_S else (2, 0)
    order = sorted(groups, key=rank); items = []
    while any(groups[k] for k in order):
        for k in order:
            if groups[k]: items.append(groups[k].pop(0))

mi = 0; o = make_orc(models[mi]); consec_err = 0; new_ok = 0
for lab, it in items:
    if it["id"] in res and (a.mode == "offline" or res[it["id"]].get("llm_status") == "ok"): continue
    if a.max_new and new_ok >= a.max_new:
        print(f"STOP: reached --max-new {a.max_new}"); break
    if consec_err >= 3:
        mi += 1
        if mi >= len(models):
            print("STOP: every model failed 3x in a row (quota/rate limit?) - rerun later; ok results are kept"); break
        print(f"switching model -> {models[mi]}"); o = make_orc(models[mi]); consec_err = 0
    o.memory_agent.reset() if hasattr(o.memory_agent, "reset") else None
    t0 = time.time()
    try:
        r = o.process_request(it["t"], persist=False, online_check=False)
        rec = {"label": lab, "kind": it.get("kind"), "score": r.get("risk_score") or 0,
               "level": (r.get("decision") or {}).get("risk_level"), "llm_status": r.get("llm_status"),
               "model": r.get("model_used"), "path": r.get("execution_path"), "ms": round((time.time() - t0) * 1000)}
    except Exception as e:
        rec = {"label": lab, "kind": it.get("kind"), "error": type(e).__name__, "ms": round((time.time() - t0) * 1000)}
    if a.mode == "llm" and rec.get("llm_status") != "ok":
        consec_err += 1
        if it["id"] in res and "score" in res[it["id"]] and res[it["id"]].get("llm_status") == "ok": continue
    else:
        consec_err = 0; new_ok += a.mode == "llm"
    res[it["id"]] = rec
    out_p.write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
    if a.pace: time.sleep(a.pace)
done = [v for v in res.values() if "score" in v]
print(f"saved {len(res)} results -> {out_p.name}; new_ok={new_ok}; errors={sum('error' in v for v in res.values())}")
if done:
    from collections import Counter
    print("llm_status:", dict(Counter(v.get("llm_status") for v in done)), "| model:", dict(Counter(v.get("model") for v in done)))
