"""Nivel 2 asistido para Tarvia SOC: correlacion, autorizaciones y matriz.

Uso desde DTT-UAB-The-Hack (sin LLM ni claves):
  python nivel2_soc.py ALR-20261005-000172 --ticket ticket_generado.json

No modifica tickets, no escribe en la API, no contiene claves ni ejecuta contencion.
Las relaciones son HIPOTESIS para revision humana; no se auto-agrupan.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
TIMEZONE = ZoneInfo("Europe/Madrid")
NIVELES = ("informational", "low", "medium", "high", "critical")
CRIT = {"baja": 0, "media": 1, "alta": 2, "crítica": 3, "critica": 3}
MATRIZ = {
    "informational": ("informational", "informational", "low", "low"),
    "low": ("informational", "low", "low", "medium"),
    "medium": ("low", "medium", "medium", "high"),
    "high": ("medium", "high", "high", "critical"),
    "critical": ("high", "critical", "critical", "critical"),
}


def leer_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def leer_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def instante(s: str) -> datetime:
    t = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ValueError("Un instante de SIEM necesita zona horaria")
    return t.astimezone(timezone.utc)


def valores(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, dict):
        return [str(x) for x in v.values() if isinstance(x, (int, float, str)) and x]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x]
    return [str(v)]


def entidades(a: dict) -> dict[str, set[str]]:
    """Indicadores con tipo: no mezclar atacante externo y activo interno."""
    e = a.get("entities") or {}
    out: dict[str, set[str]] = defaultdict(set)
    for h in e.get("hosts", []):
        if isinstance(h, dict):
            if h.get("hostname"):
                out["host"].add(h["hostname"].upper())
            if h.get("ip"):
                out["ip_host"].add(h["ip"].lower())
        elif h:
            out["host"].add(str(h).upper())
    for u in e.get("users", []):
        value = u.get("upn") or u.get("username") if isinstance(u, dict) else str(u)
        if value and not value.startswith("(") and " " not in value:
            out["user"].add(value.lower())
    for c in e.get("customers", []):
        value = c.get("customer_id") if isinstance(c, dict) else c
        if value:
            out["customer"].add(str(value).upper())
    for ip in valores(e.get("ips", [])):
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                out["ip_origen"].add(ip.lower())
        except ValueError:
            continue
    for key, tag in (("domains", "domain"), ("files", "file")):
        for x in e.get(key, []):
            if isinstance(x, str) and x:
                out[tag].add(x.lower())
            elif isinstance(x, dict):
                for k in ("sha256", "hash", "domain", "name"):
                    if x.get(k):
                        out[tag].add(str(x[k]).lower())
    for url in e.get("urls", []):
        if not isinstance(url, str):
            continue
        parsed = urlsplit(url)
        if parsed.hostname:
            out["web_host"].add(parsed.hostname.lower())
        if parsed.path and parsed.path != "/":
            out["web_path"].add(parsed.path.lower())
    cloud = e.get("cloud", {})
    if isinstance(cloud, dict):
        for key in ("identity", "principal"):
            if cloud.get(key):
                out["cloud_identity"].add(str(cloud[key]).lower())
        if cloud.get("bucket"):
            out["cloud_bucket"].add(str(cloud["bucket"]).lower())
    for ev in a.get("related_events", []):
        if isinstance(ev, str) and ev:
            out["event_id"].add(ev.upper())
    return dict(out)


def coincidencias(x: dict[str, set[str]], y: dict[str, set[str]]) -> dict[str, list[str]]:
    return {kind: sorted(x[kind] & y[kind]) for kind in (x.keys() & y.keys()) if x[kind] & y[kind]}


def tipo_relacion(seed: dict, otro: dict, match: dict[str, list[str]]) -> str | None:
    """No convertir una campaña de escaneo en un mismo incidente por coincidencia de ruta."""
    if match.get("event_id"):
        return "duplicado_evento"
    directos = any(match.get(k) for k in ("host", "user", "customer", "cloud_identity"))
    enlace = any(match.get(k) for k in ("ip_origen", "file", "domain", "web_path", "ip_host"))
    # Un mismo usuario/equipo + otra señal INDIVIDUALIZADA permite proponer grupo,
    # pero NO fusionarlo sin confirmar la cadena causal.
    if directos and (enlace or seed.get("rule_id") == otro.get("rule_id")):
        return "mismo_incidente_candidato"
    if directos or match.get("file"):
        return "relacion_investigar"
    if match.get("ip_origen") and (match.get("web_path") or match.get("domain") or seed.get("rule_id") == otro.get("rule_id")):
        return "relacion_investigar"
    if match.get("web_path") and seed.get("rule_id") == otro.get("rule_id"):
        return "campana_similar"
    return None


def sello(k: str, v: str) -> tuple[str, str]:
    return (k, v)


def relacionar(
    alerta: dict,
    alertas: list[dict],
    indice: dict[tuple[str, str], list[int]],
    features: list[dict[str, set[str]]],
    max_resultados: int = 35,
) -> dict:
    origen = entidades(alerta)
    t0 = instante(alerta["created_at"])
    ids: set[int] = set()
    for k, vs in origen.items():
        for v in vs:
            ids.update(indice.get(sello(k, v), []))
    groups: dict[str, list[dict]] = {
        "duplicado_evento": [], "mismo_incidente_candidato": [],
        "relacion_investigar": [], "campana_similar": [],
    }
    for i in ids:
        other = alertas[i]
        if other["alert_id"] == alerta["alert_id"]:
            continue
        dt = abs((instante(other["created_at"]) - t0).total_seconds())
        if dt > 24 * 3600:
            continue
        shared = coincidencias(origen, features[i])
        tipo = tipo_relacion(alerta, other, shared)
        if not tipo:
            continue
        groups[tipo].append({
            "alert_id": other["alert_id"], "producto": other.get("source_product"),
            "regla": other.get("rule_id"), "fecha_utc": other.get("created_at"),
            "minutos_diferencia": round(dt / 60, 1), "coincidencias": shared,
            "tipo": tipo,
        })
    result = {}
    for tipo, rows in groups.items():
        rows.sort(key=lambda r: (r["minutos_diferencia"], r["alert_id"]))
        result[tipo] = {"total": len(rows), "alertas": rows[:max_resultados], "truncado": len(rows) > max_resultados}
    return result


def exact_match_ip_pentest(ip: str) -> bool:
    return ip in {"192.0.2.10", "192.0.2.11", "192.0.2.12"}


def ventana_cambio_en_hora_local(cambio: dict, t_utc: datetime) -> bool:
    """El calendario no declara zona: se interpreta provisionalmente Europe/Madrid."""
    try:
        inicio = datetime.strptime(cambio["inicio"], "%Y-%m-%d %H:%M").replace(tzinfo=TIMEZONE)
        fin = datetime.strptime(cambio["fin"], "%Y-%m-%d %H:%M").replace(tzinfo=TIMEZONE)
    except (ValueError, KeyError):
        return False
    return inicio <= t_utc.astimezone(TIMEZONE) <= fin


def autorizaciones(alerta: dict, changes: list[dict]) -> dict:
    """Coincidencia estricta de TIEMPO + IDENTIDAD/ORIGEN + ALCANCE.

    Devuelve candidatos, nunca un benign_true_positive automático.
    """
    e = entidades(alerta)
    ts = instante(alerta["created_at"])
    local = ts.astimezone(TIMEZONE)
    encontrados = []
    procesos = alerta.get("entities", {}).get("processes", [])
    parents = {p.get("parent", "").lower() for p in procesos if isinstance(p, dict)}
    nombres = {p.get("name", "").lower() for p in procesos if isinstance(p, dict)}
    for ch in changes:
        if not ventana_cambio_en_hora_local(ch, ts):
            continue
        ident = ch.get("id", "")
        razones = []
        if ident == "CHG-2026-1042":
            ip_ok = any(exact_match_ip_pentest(ip) for ip in e.get("ip_origen", set()))
            host_ok = bool(e.get("web_host", set()) & {"www.tarvia.example", "api.tarvia.example"})
            if ip_ok and host_ok:
                razones = ["IP de origen incluida en el pentest", "Destino web dentro del alcance", "Fecha/hora dentro de la ventana"]
        elif ident == "CHG-2026-1031" and alerta.get("rule_id") == "UC-EDR-002":
            # El calendario dice expresamente 'diariamente 08:00-10:00'.
            # Comprobar además el proceso padre SCCM y equipo de usuario.
            if ("ccmexec.exe" in parents and "powershell.exe" in nombres
                and 8 <= local.hour < 10 and any(h.startswith("WS-") for h in e.get("host", set()))):
                razones = ["PowerShell iniciado por CcmExec.exe", "Puesto gestionado", "Horario diario SCCM 08:00-10:00"]
        elif ident.startswith("CHG-2026-10") and "Escaneo semanal de vulnerabilidades" in ch.get("titulo", ""):
            # No se deduce que un origen externo cualquiera sea NESSUS01.
            if "NESSUS01" in e.get("host", set()) and not any(h.startswith("PLC-") for h in e.get("host", set())):
                razones = ["Origen interno NESSUS01", "Cambio de escaneo semanal vigente", "No corresponde a OT"]
        elif ident == "FLUJO-0007" and alerta.get("runbook") == "RB-06":
            # DLP nómina: solo candidato, exigir destinatario concreto como evidencia.
            raw = json.dumps(alerta.get("evidence", {}), ensure_ascii=False).lower()
            if "asesoria@gestoria-pons.example" in raw:
                razones = ["Destino de nómina autorizado", "Revisar que fichero y emisor pertenezcan al flujo"]
        if razones:
            encontrados.append({"id": ident, "titulo": ch["titulo"], "justificaciones": razones,
                                 "inicio_local": ch["inicio"], "fin_local": ch["fin"]})
    return {
        "candidatos": encontrados,
        "clasificacion_automatica": None,
        "observacion": ("Posible actividad autorizada; verificar contenido, alcance y efectos antes de confirmar benign_true_positive."
                        if encontrados else "No se ha encontrado una autorización estricta entre los cambios modelados; no demuestra ausencia de autorización."),
        "zona_horaria_asumida": "Europe/Madrid (pendiente de confirmar con organizadores)",
    }


def resolver_criticidad(alerta: dict, assets: dict[str, dict], users: dict[str, dict]) -> dict:
    e = entidades(alerta)
    resueltos: dict[str, dict] = {}
    for host in e.get("host", set()):
        a = assets.get(host.lower())
        if a:
            resueltos[a["hostname"]] = a
    for ip in e.get("ip_host", set()):
        a = assets.get(ip.lower())
        if a:
            resueltos[a["hostname"]] = a
    # La URL publica resuelve al servicio web, pero NO demuestra qué nodo se vio afectado.
    if "www.tarvia.example" in e.get("web_host", set()):
        for h in ("WEB-ECOM01", "WEB-ECOM02", "WEB-ECOM03", "WEB-ECOM04"):
            a = assets.get(h.lower())
            if a:
                resueltos[h] = a
    crits = [(CRIT.get(a.get("criticality", "").lower(), -1), h) for h, a in resueltos.items()]
    crits = [(x, h) for x, h in crits if x >= 0]
    vips = []
    for user in e.get("user", set()):
        u = users.get(user.lower())
        if u and (u.get("privileged") == "True" or u.get("vip") == "True"):
            vips.append({"usuario": user, "vip": u.get("vip"), "privileged": u.get("privileged")})
    return {
        "activos_resueltos": [{"hostname": h, "criticality": a["criticality"], "business_service": a.get("business_service", "")}
                              for h, a in sorted(resueltos.items())],
        "criticidad_maxima": ("Baja", "Media", "Alta", "Crítica")[max(x for x, _ in crits)] if crits else None,
        "vip_o_privilegiados": vips,
        "advertencia": ("Los frontales son activos candidatos por destino público; no se ha demostrado que todos recibieran una petición."
                        if "www.tarvia.example" in e.get("web_host", set()) else ""),
    }


def severidad(alerta: dict, criticidad: dict, ticket: dict | None = None, autorizado: dict | None = None) -> dict:
    regla = alerta.get("severity", "")
    crit = criticidad["criticidad_maxima"]
    if regla not in MATRIZ or crit is None:
        return {"base": None, "propuesta_reglas": None, "comprobada": False,
                "avisos": ["Falta criticidad del activo/identidad: no se puede validar la matriz sin inventar un valor."]}
    base = MATRIZ[regla][CRIT[crit.lower()]]
    notas = [f"Matriz: regla {regla} × activo {crit} = {base}."]
    autor = (autorizado or {}).get("candidatos", [])
    if autor:
        notas.append("Actividad posiblemente autorizada: confirmar evidencia antes de bajar a informational/low.")
    if criticidad.get("vip_o_privilegiados"):
        notas.append("Identidad VIP/privilegiada: condición para +1 según política; verificar si está afectada realmente.")
    if alerta.get("evidence", {}).get("action") == "blocked":
        notas.append("La alerta indica bloqueo, pero -1 exige también comprobar ausencia de actividad posterior.")
    delta = 0  # Ningún ajuste automático sin confirmar las condiciones +1/-1.
    propuesta = NIVELES[max(0, min(4, NIVELES.index(base) + delta))]
    aviso = []
    if ticket:
        if ticket.get("severity") != propuesta:
            aviso.append(f"Ticket LLM declara {ticket.get('severity')}; matriz sin ajustes verificados da {propuesta}. Revisar justificación y eventos posteriores.")
        if ticket.get("verdict") == "benign_true_positive" and not autor:
            aviso.append("El ticket marca autorizado sin coincidencia estricta de calendario: exigir evidencia adicional.")
        if ticket.get("verdict") == "true_positive" and ticket.get("severity") in ("high", "critical") and not ticket.get("escalation", {}).get("escalate"):
            aviso.append("La política exige escalado de true_positive high/critical.")
    return {"base": base, "propuesta_reglas": propuesta, "ajuste_aplicado": delta,
            "comprobada": not aviso and not autor and not criticidad.get("vip_o_privilegiados") and alerta.get("evidence", {}).get("action") != "blocked",
            "notas": notas, "avisos": aviso,
            "criterio": "Los ajustes +/-1 y benign_true_positive deben verificarse con evidencia, no sólo con texto generado."}


class MotorNivel2:
    def __init__(self, root: Path = ROOT):
        self.root = Path(root)
        self.alerts = leer_jsonl(self.root / "03_alertas/alertas.jsonl")
        self.by_id = {a["alert_id"]: a for a in self.alerts}
        self.features = [entidades(a) for a in self.alerts]
        self.index: dict[tuple[str, str], list[int]] = defaultdict(list)
        for i, feats in enumerate(self.features):
            for k, vs in feats.items():
                for v in vs:
                    self.index[sello(k, v)].append(i)
        rows = leer_csv(self.root / "02_inventario/activos.csv")
        self.assets = {k.lower(): row for row in rows for k in (row.get("hostname", ""), row.get("ip", "")) if k}
        userrows = leer_csv(self.root / "02_inventario/usuarios.csv")
        self.users = {k.lower(): row for row in userrows for k in (row.get("upn", ""), row.get("username", "")) if k}
        self.changes = leer_csv(self.root / "02_inventario/calendario_cambios.csv")

    def analizar(self, alert_id: str, ticket: dict | None = None, max_resultados: int = 35) -> dict:
        if alert_id not in self.by_id:
            raise KeyError(f"La alerta no existe: {alert_id}")
        alerta = self.by_id[alert_id]
        relaciones = relacionar(alerta, self.alerts, self.index, self.features, max_resultados=max_resultados)
        cambios = autorizaciones(alerta, self.changes)
        cr = resolver_criticidad(alerta, self.assets, self.users)
        sev = severidad(alerta, cr, ticket, cambios)
        return {
            "alert_id": alert_id,
            "fuente": "dataset local del SOC; correlación por entidades y ±24h",
            "correlacion": relaciones,
            "autorizacion": cambios,
            "contexto_activo": cr,
            "severidad_politica": sev,
            "limites": [
                "Una coincidencia por IP, ruta web o regla no confirma el mismo atacante ni un mismo incidente.",
                "Candidatos de incidente: la fusión requiere revisión humana de evidencia causal y timeline.",
                "Los cambios se interpretan en Europe/Madrid; confirmar la zona horaria del calendario.",
                "No se verifica actividad posterior ni todas las fuentes de logs en este módulo de correlación.",
                "Nunca realiza contenciones ni decisiones de cierre automáticas.",
            ],
        }


def main():
    parser = argparse.ArgumentParser(description="Análisis de nivel 2 sobre alertas locales (sin IA)")
    parser.add_argument("alert_id")
    parser.add_argument("--ticket", help="Ticket N1 existente para contrastar severidad")
    parser.add_argument("--output", help="Ruta opcional para guardar informe nivel 2")
    args = parser.parse_args()
    ticket = json.loads(Path(args.ticket).read_text(encoding="utf-8")) if args.ticket else None
    if ticket and args.alert_id not in ticket.get("alert_ids", []):
        parser.error("El ticket indicado no corresponde a la alerta seleccionada")
    report = MotorNivel2().analizar(args.alert_id, ticket)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Guardado: {out}")


if __name__ == "__main__":
    main()
