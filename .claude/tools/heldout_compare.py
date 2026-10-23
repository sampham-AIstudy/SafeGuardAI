import json,pathlib
from collections import Counter,defaultdict
h=pathlib.Path.home()/'.safeguard_heldout'
A=json.loads((h/'results_v3_offline.json').read_text(encoding='utf-8'))
L=json.loads((h/'results_v3_llm.json').read_text(encoding='utf-8'))
print("n",len(A),len(L),"errors",sum('error' in v for v in L.values()))
print("llm_status",dict(Counter(v.get('llm_status') for v in L.values())))
ms=sorted(v['ms'] for v in L.values() if 'ms' in v);print("latency ms p50/p95/max",ms[len(ms)//2],ms[int(len(ms)*.95)],ms[-1])
def stats(R,subset=None):
    s=[v['score'] for v in R.values() if v.get('label')=='S' and 'score' in v and (subset is None or subset(v))]
    b=[v['score'] for v in R.values() if v.get('label')=='B' and 'score' in v and (subset is None or subset(v))]
    f=lambda x,t:sum(i>=t for i in x)
    return len(s),f(s,75),f(s,40),len(b),f(b,40),f(b,75)
ids=[k for k in A if k in L and 'score' in L[k]]
for name,R in(("A offline",A),("A+B LLM ",L)):
    n,h75,h40,m,f40,f75=stats({k:R[k] for k in ids})
    print(f"{name}: scam HIGH+ {h75}/{n} ({h75/n:.0%}) >=MED {h40}/{n} ({h40/n:.0%}) | benign FPR>=MED {f40}/{m} ({f40/m:.0%}) >=HIGH {f75}/{m} ({f75/m:.0%})")
# only cases where LLM actually answered
ok=[k for k in ids if L[k].get('llm_status')=='ok']
print("LLM ok cases",len(ok))
for name,R in(("A offline (ok subset)",A),("A+B LLM (ok subset)",L)):
    n,h75,h40,m,f40,f75=stats({k:R[k] for k in ok})
    print(f"{name}: scam HIGH+ {h75}/{n} ({h75/max(n,1):.0%}) | benign FP>=MED {f40}/{m} ({f40/max(m,1):.0%}) >=HIGH {f75}/{m}")
kd=defaultdict(lambda:[0,0,0])
for k in ids:
    v=L[k];a=A[k];key=("S:" if v['label']=='S' else "B:")+v['kind']
    thr=75 if v['label']=='S' else 40
    kd[key][0]+=1;kd[key][1]+=a['score']>=thr;kd[key][2]+=v['score']>=thr
print("kind: n  A  A+B  (scam HIGH+ / benign FP>=MED)")
for k,(n,a,l) in sorted(kd.items()):print(f"  {k}: {n} {a} -> {l}")
