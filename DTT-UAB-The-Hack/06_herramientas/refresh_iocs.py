"""Sustituye los IOCs simulados por IOCs reales y recientes (solo indicadores, nunca muestras).

Uso:  ABUSECH_AUTH_KEY=xxxx python refresh_iocs.py --src <dataset> --slots <ioc_slots.csv> --dst <copia>
Fuentes: ThreatFox, MalwareBazaar (abuse.ch, requieren Auth-Key gratuita) y lista pública de salidas Tor.
Sin red o sin clave, el dataset sigue siendo coherente con el TIP simulado: este paso es opcional.
"""
import argparse, csv, os, shutil, sys, requests

TF = "https://threatfox-api.abuse.ch/api/v1/"
MB = "https://mb-api.abuse.ch/api/v1/"
TOR = "https://check.torproject.org/torbulkexitlist"

def tf_iocs(key, malware=None, tag=None, want="ip"):
    q = {"query": "malwareinfo", "malware": malware, "limit": 50} if malware else {"query": "taginfo", "tag": tag, "limit": 50}
    r = requests.post(TF, json=q, headers={"Auth-Key": key}, timeout=30).json()
    out = []
    for i in r.get("data") or []:
        t, v = i.get("ioc_type", ""), i.get("ioc", "")
        if want == "ip" and t == "ip:port": out.append(v.split(":")[0])
        if want == "domain" and t == "domain": out.append(v)
    return out

def mb_hashes(key, sig=None, tag=None):
    q = {"query": "get_siginfo", "signature": sig, "limit": 20} if sig else {"query": "get_taginfo", "tag": tag, "limit": 20}
    r = requests.post(MB, data=q, headers={"Auth-Key": key}, timeout=30).json()
    return [i["sha256_hash"] for i in (r.get("data") or [])]

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--src", required=True); ap.add_argument("--dst", required=True); ap.add_argument("--slots", required=True); a = ap.parse_args()
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key: sys.exit("Falta ABUSECH_AUTH_KEY")
    slots = list(csv.DictReader(open(a.slots, encoding="utf-8")))
    tor = [l.strip() for l in requests.get(TOR, timeout=30).text.splitlines() if l.strip()][:20]
    plan = {}
    for s in slots:
        if s["replaceable"] != "True": continue
        fam = s["family"].lower(); new = None
        try:
            if s["type"] == "ip" and "tor" in s["tags"]:
                new = tor.pop(0) if tor else None
            elif s["type"] == "ip":
                m = {"latrodectus": "win.latrodectus", "cobalt strike": "win.cobalt_strike"}.get(fam)
                c = tf_iocs(key, malware=m) if m else tf_iocs(key, tag="xmrig" if "xmrig" in fam else "phishing" if "aitm" in fam or "evilproxy" in fam else "botnet")
                new = next((x for x in c if x not in plan.values()), None)
            elif s["type"] == "domain":
                m = {"latrodectus": "win.latrodectus", "lumma stealer": "win.lumma"}.get(fam)
                c = tf_iocs(key, malware=m, want="domain") if m else tf_iocs(key, tag="xmrig", want="domain")
                new = next((x for x in c if x not in plan.values()), None)
            elif s["type"] == "sha256":
                sig = {"latrodectus": "Latrodectus", "cobalt strike": "CobaltStrike", "lumma stealer": "LummaStealer"}.get(fam)
                c = mb_hashes(key, sig=sig) if sig else mb_hashes(key, tag="xmrig")
                new = next((x for x in c if x not in plan.values()), None)
        except Exception as e:
            print("aviso", s["slot_id"], e)
        if new:
            plan[s["value"]] = new; print(f"{s['slot_id']}: {s['value']} -> {new}")
        else:
            print(f"{s['slot_id']}: sin sustituto, se mantiene el simulado")
    shutil.copytree(a.src, a.dst, dirs_exist_ok=True)
    for root, _, files in os.walk(a.dst):
        for fn in files:
            if not fn.endswith((".jsonl", ".csv", ".json", ".md")): continue
            path = os.path.join(root, fn); txt = open(path, encoding="utf-8").read(); orig = txt
            for old, new in plan.items(): txt = txt.replace(old, new)
            if txt != orig: open(path, "w", encoding="utf-8").write(txt)
    print(f"{len(plan)} indicadores sustituidos en {a.dst}")

if __name__ == "__main__":
    main()
