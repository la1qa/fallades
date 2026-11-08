"""Càlcul DETERMINISTA de la severitat final d'un cas (alerta o grup d'alertes).

   severitat = MATRIU(severitat de la regla x criticitat afectada)
             + POLÍTICA  (màx. un nivell amunt o avall EN TOTAL, política SOC apartat 2)
             + CORRELACIÓ (adaptació nostra; un sol terme, a part del límit de la política):
                  +1 si és una CADENA d'atac confirmada
                  -1 si és un PATRÓ MASSIU BENIGNE verificat
                   0 en qualsevol altre cas

Qui decideix què: el model diu en quin cas creu que som (factores["correlation"]) i aporta proves;
el CODI comprova les condicions i és qui aplica (o ignora) l'ajust.

Ús:   import severidad ; severidad.aplicar_a_ticket(ticket, alertas, get, patron=None)
Test: python severidad.py --test
"""
import sys
from urllib.parse import quote

LEVELS = ["informational", "low", "medium", "high", "critical"]
RANK = {"Baja": 0, "Media": 1, "Alta": 2, "Crítica": 3}
MATRIX = {   # fila = severitat de la regla ; columna = criticitat de l'actiu (política SOC, apartat 2)
    "informational": {"Baja": "informational", "Media": "informational", "Alta": "low", "Crítica": "low"},
    "low":      {"Baja": "informational", "Media": "low", "Alta": "low", "Crítica": "medium"},
    "medium":   {"Baja": "low", "Media": "medium", "Alta": "medium", "Crítica": "high"},
    "high":     {"Baja": "medium", "Media": "high", "Alta": "high", "Crítica": "critical"},
    "critical": {"Baja": "high", "Media": "critical", "Alta": "critical", "Crítica": "critical"},
}
# Llindars per acceptar un "patró massiu benigne" (PROPOSTA: ajusteu-los mirant els patrons reals)
PATRON_MIN = {"alertas": 50, "usuarios": 20, "dias": 7}
MIN_FUENTES = 2          # proves de >= 2 fonts diferents per acceptar cadena o patró benigne


def _ok(d):
    return bool(d) and not d.get("not_found")


def _cert(x):
    return str(x).strip().lower() == "true"


# ---------- dades que ve el CODI (no el model) ----------
def criticidad_afectada(alertas, get):
    """Criticitat més alta entre els equips de l'alerta, l'equip de cada usuari i el frontal web (WAF)."""
    candidats, vistos = [], set()

    def actiu(host, origen):
        if host in vistos:
            return
        vistos.add(host)
        d = get(f"/assets/{quote(host, safe='')}")
        if _ok(d) and d.get("criticality") in RANK:
            candidats.append((d["criticality"], f"{origen} {host}"))

    for a in alertas:
        e = a.get("entities", {})
        for h in e.get("hosts", []):
            actiu(h["hostname"], "equip")
        for u in e.get("users", []):
            upn = u.get("upn", "")
            if "@" in upn:
                d = get(f"/users/{quote(upn, safe='')}")
                if _ok(d) and d.get("workstation"):
                    actiu(d["workstation"], f"equip de {upn.split('@')[0]}:")
        if a.get("source_product") == "WAF":
            actiu("WEB-ECOM01", "frontal web")
    if not candidats:
        return {"nivel": "Media", "origen": "cap actiu a la CMDB: s'assumeix Media", "assumida": True}
    nivel, origen = max(candidats, key=lambda c: RANK[c[0]])
    return {"nivel": nivel, "origen": origen, "assumida": False}


def identidades_vip_o_priv(alertas, get):
    out = []
    for a in alertas:
        for u in a.get("entities", {}).get("users", []):
            upn = u.get("upn", "")
            if "@" in upn:
                d = get(f"/users/{quote(upn, safe='')}")
                if _ok(d) and (_cert(d.get("vip")) or _cert(d.get("privileged"))) and upn not in out:
                    out.append(upn)
    return out


def estadisticas_patron(indicador, todas, ids_en_cadena=(), alerta_id=None):
    """Estadístiques d'un patró massiu: quantes alertes, usuaris i dies comparteixen l'indicador."""
    n, usuaris, dies = 0, set(), set()
    for a in todas:
        e = a.get("entities", {})
        ents = set(e.get("ips", [])) | set(e.get("domains", [])) | {f.get("sha256") for f in e.get("files", [])}
        if indicador in ents:
            n += 1
            dies.add(a["created_at"][:10])
            usuaris |= {u["upn"] for u in e.get("users", []) if "@" in u.get("upn", "")}
    return {"indicador": indicador, "n_alertas": n, "n_usuarios": len(usuaris), "n_dias": len(dies),
            "en_cadena": alerta_id in set(ids_en_cadena)}


# ---------- el terme de CORRELACIÓ ----------
def evaluar_correlacion(factores, n_alertas, n_reglas, fuentes, patron, get):
    """Retorna (delta, text). +1 cadena confirmada, -1 patró benigne verificat, 0 en cas contrari."""
    corr = factores.get("correlation") or ("chain" if factores.get("chain_confirmed") else "none")
    if corr == "chain":
        if n_alertas < 2 or n_reglas < 2:
            return 0, "Cadena indicada però ignorada: no és un grup de >=2 alertes i >=2 regles."
        if fuentes < MIN_FUENTES:
            return 0, f"Cadena indicada però ignorada: el tiquet no cita proves de >={MIN_FUENTES} fonts."
        return 1, "Correlació +1: cadena d'atac confirmada (fora del límit de la política)."
    if corr == "benign_pattern":
        if not patron:
            return 0, "Patró benigne indicat però ignorat: no hi ha estadístiques del patró."
        falla = []
        if patron["n_alertas"] < PATRON_MIN["alertas"]:
            falla.append(f"només {patron['n_alertas']} alertes (cal >={PATRON_MIN['alertas']})")
        if patron["n_usuarios"] < PATRON_MIN["usuarios"]:
            falla.append(f"només {patron['n_usuarios']} usuaris (cal >={PATRON_MIN['usuarios']})")
        if patron["n_dias"] < PATRON_MIN["dias"]:
            falla.append(f"només {patron['n_dias']} dies (cal >={PATRON_MIN['dias']})")
        if patron.get("en_cadena"):
            falla.append("l'alerta forma part d'una cadena")
        d = get(f"/intel/{quote(patron['indicador'], safe='')}")
        rep = ((d.get("tip") or {}).get("reputation") if _ok(d) else None)
        if rep in ("malicious", "suspicious"):
            falla.append(f"el TIP el marca com a {rep}")
        if fuentes < MIN_FUENTES:
            falla.append(f"proves de <{MIN_FUENTES} fonts")
        if falla:
            return 0, "Patró benigne indicat però ignorat: " + "; ".join(falla) + "."
        return -1, (f"Correlació -1: patró massiu benigne verificat ({patron['n_alertas']} alertes, "
                    f"{patron['n_usuarios']} usuaris, {patron['n_dias']} dies, no és en cadena).")
    return 0, ""


def severidad_final(sev_regla, criticidad, factores, veredicto="true_positive", n_alertas=1, n_reglas=1,
                    fuentes=0, patron=None, get=None):
    f = factores or {}
    base = MATRIX[sev_regla][criticidad]
    d_cor, txt_cor = evaluar_correlacion(f, n_alertas, n_reglas, fuentes, patron, get or (lambda *a, **k: None))
    sube = [m for k, m in (("confirmed_execution_or_access", "execució/accés confirmat"),
                           ("vip_or_privileged_identity", "identitat VIP/privilegiada"),
                           ("personal_or_payment_data", "dades personals o pagaments")) if f.get(k)]
    baixa = bool(f.get("blocked_without_effect")) and d_cor <= 0     # una cadena implica activitat posterior
    d_pol = max(-1, min(1, (1 if sube else 0) - (1 if baixa else 0)))      # política: màxim ±1 EN TOTAL
    idx = max(0, min(4, LEVELS.index(base) + d_pol + d_cor))
    sev, nota = LEVELS[idx], ""
    if veredicto == "benign_true_positive" and idx > 1:
        sev, nota = "low", " Veredicte benigne autoritzat: topall a low (política)."
    elif veredicto == "false_positive" and idx > 0:
        sev, nota = "informational", " Fals positiu: informational (criteri de l'equip)."
    txt = f"Regla {sev_regla} x actiu {criticidad} = {base}. Política {d_pol:+d}"
    txt += (f" ({', '.join(sube)})" if sube else "") + (" (bloquejat sense efecte)" if baixa else "") + " [màx. ±1]."
    if txt_cor:
        txt += " " + txt_cor
    return sev, txt + f" Severitat final: {sev}." + nota


def aplicar_a_ticket(ticket, alertas, get, patron=None):
    """Substitueix la severitat del model per la calculada pel codi i en deixa la traça."""
    sev_regla = max((a["severity"] for a in alertas), key=LEVELS.index)
    crit = criticidad_afectada(alertas, get)
    vips = identidades_vip_o_priv(alertas, get)
    factores = dict(ticket.get("factores") or {})
    factores["vip_or_privileged_identity"] = bool(vips)         # ho decideix el directori, no el model
    fonts = {e.get("source") for e in ticket.get("evidence", []) if isinstance(e, dict) and e.get("source")}
    sev, txt = severidad_final(sev_regla, crit["nivel"], factores, ticket.get("verdict", ""),
                               len(alertas), len({a["rule_id"] for a in alertas}), len(fonts), patron, get)
    ticket["severity_model"] = ticket.get("severity")            # per comparar el model amb el codi
    ticket["severity"] = sev
    ticket["severity_rationale"] = txt + f" Criticitat: {crit['origen']}" + (" (supòsit)." if crit["assumida"] else ".")
    ticket["severity_calc"] = {"regla": sev_regla, "criticitat": crit, "vip_o_privilegiats": vips,
                               "factores": factores, "patron": patron}
    return ticket


# ---------- autotest ----------
def _test():
    tip = {"bo": {"tip": {"reputation": "benign"}}, "mal": {"tip": {"reputation": "malicious"}}, "res": {"tip": None}}
    get = lambda path, **p: tip.get(path.split("/")[-1], {"not_found": True})
    P = lambda **k: {"indicador": "res", "n_alertas": 300, "n_usuarios": 250, "n_dias": 28, "en_cadena": False, **k}
    C = lambda **k: k
    casos = [  # (nom, args, kwargs, esperat)
        ("low x Baja = informational", ("low", "Baja", C()), {}, "informational"),
        ("high x Crítica, +1 topall", ("high", "Crítica", C(confirmed_execution_or_access=True)), {}, "critical"),
        ("medium x Media + execució = high", ("medium", "Media", C(confirmed_execution_or_access=True)), {}, "high"),
        ("low x Media bloquejat = informational", ("low", "Media", C(blocked_without_effect=True)), {}, "informational"),
        ("3 motius de +1 = UN sol nivell", ("medium", "Media", C(confirmed_execution_or_access=True,
            vip_or_privileged_identity=True, personal_or_payment_data=True)), {}, "high"),
        ("cadena: low x Media + execució + cadena = high", ("low", "Media", C(confirmed_execution_or_access=True,
            correlation="chain")), dict(n_alertas=4, n_reglas=3, fuentes=2), "high"),
        ("cadena sola = +1", ("low", "Media", C(correlation="chain")), dict(n_alertas=3, n_reglas=3, fuentes=2), "medium"),
        ("cadena anul·la el -1 de bloqueig", ("low", "Media", C(blocked_without_effect=True, correlation="chain")),
            dict(n_alertas=3, n_reglas=3, fuentes=2), "medium"),
        ("cadena ignorada: 1 sola alerta", ("low", "Media", C(correlation="chain")), dict(n_alertas=1, n_reglas=1, fuentes=2), "low"),
        ("cadena ignorada: 1 sola regla", ("low", "Media", C(correlation="chain")), dict(n_alertas=5, n_reglas=1, fuentes=2), "low"),
        ("cadena ignorada: proves d'1 font", ("low", "Media", C(correlation="chain")), dict(n_alertas=3, n_reglas=3, fuentes=1), "low"),
        ("patró benigne verificat = -1", ("medium", "Media", C(correlation="benign_pattern")),
            dict(patron=P(), fuentes=2, get=get), "low"),
        ("patró benigne amb TIP benign = -1", ("medium", "Media", C(correlation="benign_pattern")),
            dict(patron=P(indicador="bo"), fuentes=2, get=get), "low"),
        ("patró ignorat: TIP malicious", ("medium", "Media", C(correlation="benign_pattern")),
            dict(patron=P(indicador="mal"), fuentes=2, get=get), "medium"),
        ("patró ignorat: massa petit", ("medium", "Media", C(correlation="benign_pattern")),
            dict(patron=P(n_alertas=10), fuentes=2, get=get), "medium"),
        ("patró ignorat: l'alerta és en una cadena", ("medium", "Media", C(correlation="benign_pattern")),
            dict(patron=P(en_cadena=True), fuentes=2, get=get), "medium"),
        ("patró ignorat: proves d'1 font", ("medium", "Media", C(correlation="benign_pattern")),
            dict(patron=P(), fuentes=1, get=get), "medium"),
        ("patró ignorat: sense estadístiques", ("medium", "Media", C(correlation="benign_pattern")),
            dict(fuentes=2, get=get), "medium"),
        ("política -1 + patró -1 = -2 (high -> low)", ("high", "Media", C(blocked_without_effect=True,
            correlation="benign_pattern")), dict(patron=P(), fuentes=2, get=get), "low"),
        ("màxim possible: política +1 i cadena +1", ("medium", "Alta", C(confirmed_execution_or_access=True,
            correlation="chain")), dict(n_alertas=3, n_reglas=3, fuentes=2), "critical"),
        ("benign_true_positive topall a low", ("high", "Crítica", C(), "benign_true_positive"), {}, "low"),
        ("false_positive = informational", ("medium", "Alta", C(), "false_positive"), {}, "informational"),
        ("compatibilitat: chain_confirmed=True", ("low", "Media", C(chain_confirmed=True)),
            dict(n_alertas=3, n_reglas=3, fuentes=2), "medium"),
    ]
    mal = 0
    for nom, args, kw, esperat in casos:
        sev, _ = severidad_final(*args, **kw)
        ok = sev == esperat
        mal += not ok
        print(f"{'OK ' if ok else 'ERR'} {nom:<50} -> {sev}" + ("" if ok else f"  (esperat {esperat})"))
    print("\nTot correcte" if not mal else f"\n{mal} errors")
    return mal


if __name__ == "__main__":
    sys.exit(_test() if "--test" in sys.argv else print(__doc__))
