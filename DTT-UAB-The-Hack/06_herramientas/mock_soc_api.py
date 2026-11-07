"""API simulada del SOC de Tarvia. Lee los ficheros del dataset; no tiene red ni efectos reales."""
import csv, json, os, uuid, datetime as dt
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
p = lambda *x: os.path.join(BASE, *x)

def jl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]
def cs(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))

ALERTS = {a["alert_id"]: a for a in jl(p("03_alertas", "alertas.jsonl"))}
ASSETS = cs(p("02_inventario", "activos.csv")); USERS = cs(p("02_inventario", "usuarios.csv"))
VULNS = cs(p("02_inventario", "vulnerabilidades.csv")); HR = cs(p("02_inventario", "eventos_rrhh.csv"))
CHANGES = cs(p("02_inventario", "calendario_cambios.csv"))
TI = {r["value"]: r for r in jl(p("05_inteligencia", "ti_feed.jsonl"))}
GEO = {r["ip"]: r for r in cs(p("05_inteligencia", "geoip_asn.csv"))}
SBX = {r["sha256"]: r for r in jl(p("05_inteligencia", "sandbox_informes.jsonl"))}
LOGDIR = p("04_logs"); _cache = {}
APPROVALS = {}; LOGFILE = p("06_herramientas", "containment_log.jsonl")

def logs(src):
    if src not in _cache:
        if os.path.exists(os.path.join(LOGDIR, src + ".jsonl")):
            _cache[src] = jl(os.path.join(LOGDIR, src + ".jsonl"))
        elif os.path.exists(os.path.join(LOGDIR, src + ".csv")):
            _cache[src] = cs(os.path.join(LOGDIR, src + ".csv"))
        else:
            raise HTTPException(404, f"fuente desconocida: {src}")
    return _cache[src]

app = FastAPI(title="Tarvia SOC (simulado)", version="1.0")

@app.get("/alerts")
def list_alerts(status: str = "new", desde: str = "", hasta: str = "", rule_id: str = "", limit: int = 50, offset: int = 0):
    rows = [a for a in ALERTS.values() if a["status"] == status and (not rule_id or a["rule_id"] == rule_id)
            and (not desde or a["created_at"] >= desde) and (not hasta or a["created_at"] <= hasta)]
    return {"total": len(rows), "items": rows[offset:offset + limit]}

@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    if alert_id not in ALERTS: raise HTTPException(404)
    return ALERTS[alert_id]

@app.get("/assets/{key}")
def get_asset(key: str):
    a = next((x for x in ASSETS if x["hostname"].lower() == key.lower() or x["ip"] == key), None)
    if not a: raise HTTPException(404, "no está en la CMDB (¿equipo externo o no gestionado?)")
    return {**a, "vulnerabilities": [v for v in VULNS if v["hostname"] == a["hostname"]]}

@app.get("/users/{key}")
def get_user(key: str):
    k = key.lower()
    u = next((x for x in USERS if x["upn"].lower() == k or x["username"].lower() == k), None)
    if not u: raise HTTPException(404)
    return {**u, "hr_events": [h for h in HR if h["usuario"] == u["upn"]]}

@app.get("/logs/{source}")
def search_logs(source: str, q: str = "", desde: str = "", hasta: str = "", limit: int = Query(200, le=2000)):
    out = []
    for e in logs(source):
        t = e.get("timestamp") or e.get("eventTime", "")
        if desde and t < desde: continue
        if hasta and t > hasta: continue
        if q and q.lower() not in json.dumps(e, ensure_ascii=False).lower(): continue
        out.append(e)
        if len(out) >= limit: break
    return {"count": len(out), "truncated": len(out) >= limit, "items": out}

@app.get("/intel/{indicator}")
def intel(indicator: str):
    return {"indicator": indicator, "tip": TI.get(indicator), "geo": GEO.get(indicator)}

@app.get("/sandbox/{sha256}")
def sandbox(sha256: str):
    if sha256 not in SBX: raise HTTPException(404, "sin informe: el fichero no se ha enviado a la sandbox")
    return SBX[sha256]

@app.get("/changes")
def changes(q: str = ""):
    return [c for c in CHANGES if q.lower() in json.dumps(c, ensure_ascii=False).lower()]

class Approval(BaseModel):
    action: str; target: str; approver: str; reason: str = ""

@app.post("/approvals")
def approve(a: Approval):
    tok = "APR-" + uuid.uuid4().hex[:10]
    APPROVALS[tok] = a.model_dump()
    return {"approval_token": tok, **a.model_dump()}

class Action(BaseModel):
    target: str; justification: str; approval_token: str = ""; ticket_id: str = ""

NO_APPROVAL = {"block_ioc", "purge_email"}
VALID = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email", "disable_access_key"}

@app.post("/containment/{action}")
def contain(action: str, a: Action):
    if action not in VALID: raise HTTPException(400, f"acción no soportada: {action}")
    if action not in NO_APPROVAL:
        ap = APPROVALS.get(a.approval_token)
        if not ap or ap["action"] != action or ap["target"] != a.target:
            raise HTTPException(403, "falta aprobación humana válida para esta acción y objetivo")
    if action == "isolate_host":
        asset = next((x for x in ASSETS if x["hostname"] == a.target), None)
        if asset and asset["zone"] == "LOGISTICS-OT":
            raise HTTPException(403, "política: el SOC no actúa sobre OT; escalar a Operaciones")
    rec = {"timestamp": dt.datetime.utcnow().isoformat() + "Z", "action": action, **a.model_dump(), "result": "ok (simulado)"}
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec

@app.get("/containment/log")
def contain_log():
    return jl(LOGFILE) if os.path.exists(LOGFILE) else []
