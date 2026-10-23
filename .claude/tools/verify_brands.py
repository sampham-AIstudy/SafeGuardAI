r"""Evidence-gathering for vn_brands.json official domains (READ-ONLY network: one HTTPS GET per domain).
Usage: .venv\Scripts\python.exe -I .claude\tools\verify_brands.py   -> writes ~/.safeguard_heldout/brand_evidence.json
Per domain: DNS ok, TLS handshake validated by system CA, cert SAN covers the domain, cert organisation, final URL after
redirects (host stays in same registrable family?), <title>. Page content is never stored beyond the title. Untrusted data."""
import json, re, socket, ssl, sys, urllib.request, urllib.error
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")
brands = json.loads(Path("codebase/knowledge_base/vn_brands.json").read_text(encoding="utf-8"))["brands"]
ctx = ssl.create_default_context()
UA = {"User-Agent": "Mozilla/5.0 (compatible; SafeGuardAI-brand-check/1.0)"}

def san_ok(cert, dom):
    sans = [v.lower() for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    for host in (dom, "www." + dom):
        for s in sans:
            if s == host or (s.startswith("*.") and host.endswith(s[1:]) and host.count(".") == s.count(".")):
                return True
    return False

def probe(dom):
    out = {"domain": dom}
    for host in (dom, "www." + dom):
        try:
            with socket.create_connection((host, 443), timeout=10) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
            subj = {k: v for t in cert.get("subject", ()) for k, v in t}
            out.update(host=host, tls_ok=True, san_covers=san_ok(cert, dom), cert_org=subj.get("organizationName"),
                       cert_cn=subj.get("commonName"), issuer=dict(x[0] for x in cert.get("issuer", ())).get("organizationName"))
            break
        except Exception as e:
            out.update(tls_ok=False, error=type(e).__name__)
    if out.get("tls_ok"):
        try:
            req = urllib.request.Request("https://" + out["host"] + "/", headers=UA)
            with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
                body = r.read(200_000).decode("utf-8", "ignore")
                out["final_url"] = r.geturl()[:200]
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else None
        except Exception as e:
            out["http_error"] = type(e).__name__
    return out

ev = {}
for b in brands:
    ev[b["brand_id"]] = {"name": b["display_name"], "domains": [probe(d) for d in b["official_domains"]]}
    ok = sum(1 for x in ev[b["brand_id"]]["domains"] if x.get("tls_ok") and x.get("san_covers"))
    print(f"{b['brand_id']:<16} {ok}/{len(b['official_domains'])} tls+san ok")
out = Path.home() / ".safeguard_heldout" / "brand_evidence.json"
out.write_text(json.dumps(ev, ensure_ascii=False, indent=1), encoding="utf-8")
print("saved", out)
