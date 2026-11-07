"""Prova l'agent DCC amb alertes de cada tipologia (runbook) i mostra què dona.

Posa aquest fitxer al costat d'agente_soc_dcc.py (arrel del projecte).
Necessites: API del SOC encesa (port 8000) i DCC_API_KEY posada al terminal.

    python probar_runbooks.py                       # 1 alerta aleatòria de cada runbook
    python probar_runbooks.py --runbooks RB-01 RB-05 # només aquests runbooks
    python probar_runbooks.py --n 2                 # 2 alertes per runbook
    python probar_runbooks.py --seed 7              # repetir exactament la mateixa tria
"""
import argparse, collections, contextlib, io, json, os, random, sys, time
from datetime import datetime
from urllib.parse import quote

import agente_soc_dcc as ag

PREFIX_TO_LOG = {"EDR": "edr_events", "EML": "email", "DNS": "dns", "WAF": "waf", "FW": "firewall",
                 "PRX": "proxy", "CLK": "email_clicks", "DLP": "dlp", "SIGN": "idp_signins",
                 "AIG": "ai_gateway", "ECO": "ecom_auth", "VPN": "vpn", "CT": "cloudtrail",
                 "ECA": "ecom_account", "ADE": "ad_events"}


class SoloTraza(io.TextIOBase):
    """Deixa passar només les línies [SOC API] i [IA] (el rastre); amaga el JSON llarg."""
    def __init__(self, real):
        self.real, self.buf = real, ""
    def write(self, s):
        self.buf += s
        while "\n" in self.buf:
            linia, self.buf = self.buf.split("\n", 1)
            if linia.startswith(("[SOC API]", "[IA]")):
                self.real.write("     " + linia + "\n")
                self.real.flush()
        return len(s)
    def flush(self):
        self.real.flush()


def cargar_muestra():
    ruta = ag.ROOT / "03_alertas" / "alertas_muestra_desarrollo.jsonl"
    return [json.loads(l) for l in ruta.read_text(encoding="utf-8").splitlines() if l.strip()]


def verificar_ids(ticket):
    """Comprova que cada event_id citat com a evidència existeix de debò als logs."""
    ok = total = 0
    antes = os.environ.get("SOC_VERBOSE")
    os.environ["SOC_VERBOSE"] = "0"
    try:
        for ev in ticket.get("evidence", []):
            eid = str(ev.get("event_id", ""))
            fuente = PREFIX_TO_LOG.get(eid.split("-")[0])
            total += 1
            if fuente:
                try:
                    r = ag.get(f"/logs/{fuente}", q=eid, limit=1)
                    ok += bool(r.get("items"))
                except Exception:
                    pass
    finally:
        if antes is None:
            os.environ.pop("SOC_VERBOSE", None)
        else:
            os.environ["SOC_VERBOSE"] = antes
    return ok, total


def mostrar(rb, alerta, t, segundos, ids):
    print(f"\n   ➜ VEREDICTE: {t['verdict']}  | SEVERITAT: {t['severity']} (regla: {alerta['severity']})"
          f"  | CONFIANÇA: {t['confidence']}  | {segundos:.0f}s")
    print(f"   Títol: {t['title']}")
    print(f"   Resum: {t['summary'][:400]}")
    print(f"   Severitat, raó: {t.get('severity_rationale', '')[:250]}")
    print(f"   Evidències: {len(t['evidence'])}  (IDs reals als logs: {ids[0]}/{ids[1]})")
    for a in t.get("recommended_actions", []):
        print(f"   Acció: {a['action']} → {a['target']}  (cal aprovació: {a['requires_approval']})")
    if t.get("open_questions"):
        print(f"   Preguntes obertes: {'; '.join(t['open_questions'])[:250]}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=1, help="alertes per runbook")
    p.add_argument("--runbooks", nargs="*", help="p. ex. RB-01 RB-05 (per defecte, tots)")
    p.add_argument("--seed", type=int, help="per repetir la mateixa tria")
    args = p.parse_args()

    try:
        ag.get("/alerts", limit=1)
    except Exception:
        sys.exit(f"✖ L'API del SOC no respon a {ag.BASE}. Engega-la en un altre terminal:\n"
                 "    cd 06_herramientas ; uvicorn mock_soc_api:app --port 8000")

    seed = args.seed if args.seed is not None else random.randrange(10**6)
    rng = random.Random(seed)
    por_rb = collections.defaultdict(list)
    for a in cargar_muestra():
        por_rb[a["runbook"]].append(a)
    elegidas = []
    for rb in sorted(por_rb):
        if args.runbooks and rb not in args.runbooks:
            continue
        elegidas += [(rb, a) for a in rng.sample(por_rb[rb], min(args.n, len(por_rb[rb])))]

    carpeta = ag.ROOT / "resultados" / datetime.now().strftime("%Y%m%d_%H%M%S")
    carpeta.mkdir(parents=True, exist_ok=True)
    print(f"Llavor: {seed} (per repetir: --seed {seed}) · {len(elegidas)} alertes · guardant a {carpeta}")

    resumen = []
    for i, (rb, a) in enumerate(elegidas, 1):
        print(f"\n{'=' * 78}\n[{i}/{len(elegidas)}] {rb} · {a['alert_id']} · {a['rule_name']}\n{'=' * 78}")
        alerta = ag.get(f"/alerts/{quote(a['alert_id'], safe='')}")
        if alerta.get("not_found"):
            alerta = a
        salida = ag.ROOT / "ticket_generado.json"
        salida.unlink(missing_ok=True)
        t0 = time.perf_counter()
        try:
            with contextlib.redirect_stdout(SoloTraza(sys.stdout)):
                ag.agente_main(alerta)
            ticket = json.loads(salida.read_text(encoding="utf-8"))
            seg = time.perf_counter() - t0
            ids = verificar_ids(ticket)
            mostrar(rb, alerta, ticket, seg, ids)
            (carpeta / f"{a['alert_id']}.json").write_text(
                json.dumps(ticket, indent=2, ensure_ascii=False), encoding="utf-8")
            resumen.append((rb, a["alert_id"], alerta["severity"], ticket["verdict"], ticket["severity"],
                            ticket["confidence"], f"{ids[0]}/{ids[1]}", f"{seg:.0f}s", ""))
        except SystemExit as e:                      # p. ex. falta la clau
            print(f"\n   ✖ Aturat: {e}")
            break
        except Exception as e:
            print(f"\n   ✖ ERROR: {type(e).__name__}: {str(e)[:300]}")
            resumen.append((rb, a["alert_id"], alerta["severity"], "ERROR", "-", "-", "-",
                            f"{time.perf_counter() - t0:.0f}s", type(e).__name__))

    print(f"\n\n{'=' * 78}\nRESUM\n{'=' * 78}")
    print(f"{'RB':<6}{'alerta':<22}{'regla':<10}{'veredicte':<22}{'sever.':<10}{'conf.':<7}{'IDs':<6}{'temps':<6}")
    for r in resumen:
        print(f"{r[0]:<6}{r[1]:<22}{r[2]:<10}{r[3]:<22}{r[4]:<10}{str(r[5]):<7}{r[6]:<6}{r[7]:<6}{r[8]}")
    (carpeta / "_resum.json").write_text(json.dumps(resumen, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
