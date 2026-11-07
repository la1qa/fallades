#!/usr/bin/env python3
"""Lote SOC N1: un JSON independiente y validado por alerta.

Usa el agente existente adaptado en agente_soc_dcc_v2.py.
  python analizar_alertas.py
  python generar_15_tickets_v2.py --dry-run
  python generar_15_tickets_v2.py --limit 1
  python generar_15_tickets_v2.py --limit 15
  python generar_15_tickets_v2.py --verify-only

Requiere DCC_API_KEY en secretos Codespaces, y API SOC activa en puerto 8000.
SOLO consulta fuentes de lectura; nunca invoca contencion ni aprobaciones.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

VERDICTS = {"true_positive", "benign_true_positive", "false_positive", "needs_more_info"}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
COLUMNS = ["alert_id", "producto", "runbook", "estado", "verdict", "severity", "confidence",
           "triage_seconds", "archivo", "detalle"]


def leer_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def guardar_json_atomicamente(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def validar_completo(path: Path, alert_id: str, schema: dict):
    """Valida estructura Y campos importantes; no certifica que el LLM diga la verdad."""
    from jsonschema import Draft202012Validator

    ticket = leer_json(path)
    errores = list(Draft202012Validator(schema).iter_errors(ticket))
    if errores:
        raise ValueError("JSON Schema: " + "; ".join(e.message for e in errores[:3]))
    campos = ["ticket_id", "title", "summary", "severity_rationale", "verdict", "severity",
              "affected", "evidence", "enrichment", "mitre", "recommended_actions",
              "escalation", "open_questions", "executed_actions", "triage_seconds"]
    faltan = [k for k in campos if k not in ticket]
    if faltan:
        raise ValueError("Faltan campos completos: " + ", ".join(faltan))
    if alert_id not in ticket.get("alert_ids", []):
        raise ValueError("El ticket no contiene la alerta investigada")
    if not str(ticket["ticket_id"]).strip() or not str(ticket["title"]).strip():
        raise ValueError("Ticket sin titulo o identificador")
    if len(str(ticket["summary"]).strip()) < 35:
        raise ValueError("Resumen vacío o demasiado breve")
    if len(str(ticket["severity_rationale"]).strip()) < 20:
        raise ValueError("Falta justificacion real de la severidad")
    if ticket["verdict"] not in VERDICTS or ticket["severity"] not in SEVERITIES:
        raise ValueError("Veredicto o severidad no admitidos")
    if not isinstance(ticket["affected"], dict) or any(
        not isinstance(ticket["affected"].get(k), list)
        for k in ("users", "hosts", "business_services", "customers")
    ):
        raise ValueError("Affected incompleto (users/hosts/business_services/customers)")
    if not isinstance(ticket["evidence"], list) or not ticket["evidence"]:
        raise ValueError("No hay evidencias documentadas")
    for i, ev in enumerate(ticket["evidence"]):
        if not isinstance(ev, dict) or any(not str(ev.get(k, "")).strip() for k in
                                           ("source", "event_id", "finding")):
            raise ValueError(f"Evidencia {i + 1} sin fuente, ID/referencia o hallazgo")
    if not isinstance(ticket["enrichment"], list) or not isinstance(ticket["mitre"], list):
        raise ValueError("Faltan arrays de inteligencia/MITRE")
    actions = ticket["recommended_actions"]
    if not isinstance(actions, list) or not actions:
        raise ValueError("Falta recomendacion concreta: cerrar, escalar o investigar mas")
    for i, act in enumerate(actions):
        if not isinstance(act, dict) or any(not str(act.get(k, "")).strip()
                                           for k in ("action", "target", "justification")):
            raise ValueError(f"Accion recomendada {i + 1} incompleta")
        if not isinstance(act.get("requires_approval"), bool):
            raise ValueError(f"Accion recomendada {i + 1} sin requires_approval booleano")
    esc = ticket["escalation"]
    if (not isinstance(esc, dict) or not isinstance(esc.get("escalate"), bool)
            or not str(esc.get("reason", "")).strip()):
        raise ValueError("Escalado sin decision y justificacion")
    if esc["escalate"] and not str(esc.get("to", "")).strip():
        raise ValueError("Escalado afirmativo sin destino")
    if not isinstance(ticket["open_questions"], list):
        raise ValueError("open_questions debe ser una lista")
    if ticket["executed_actions"] != []:
        raise ValueError("Hay acciones ejecutadas: fuera del alcance del lote N1")
    if not isinstance(ticket["triage_seconds"], (int, float)) or ticket["triage_seconds"] < 0:
        raise ValueError("triage_seconds incorrecto")
    return ticket


def api_disponible(base: str):
    try:
        with urlopen(base.rstrip("/") + "/openapi.json", timeout=8) as resp:
            return resp.status == 200
    except Exception:
        return False


def guardar_metricas(root: Path, registros: list[dict]):
    destino = root / "resultados/metricas_tickets.csv"
    destino.parent.mkdir(parents=True, exist_ok=True)
    with destino.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for r in registros:
            writer.writerow({c: r.get(c, "") for c in COLUMNS})
    return destino


def ejecutar_agente(agente: Path, aid: str, archivo: Path, logpath: Path,
                    entorno: dict, timeout: int):
    t0 = time.monotonic()
    with logpath.open("w", encoding="utf-8") as logfile:
        proc = subprocess.Popen([sys.executable, "-u", str(agente), aid],
                                stdout=logfile, stderr=subprocess.STDOUT,
                                cwd=str(agente.parent), env=entorno)
        try:
            while True:
                try:
                    code = proc.wait(timeout=15)
                    return code, False, round(time.monotonic() - t0, 2)
                except subprocess.TimeoutExpired:
                    elapsed = int(time.monotonic() - t0)
                    print(f"    Investigando {aid}... {elapsed}s | {logpath.name}", flush=True)
                    if elapsed >= timeout:
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                        return proc.returncode, True, round(time.monotonic() - t0, 2)
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            raise


def main():
    p = argparse.ArgumentParser(description="Un JSON completo e independiente por alerta")
    p.add_argument("--limit", type=int, default=15)
    p.add_argument("--model", default="ornith", choices=["ornith", "nemotron"])
    p.add_argument("--turns", type=int, default=24)
    p.add_argument("--timeout", type=int, default=600, help="Segundos por alerta")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verify-only", action="store_true", help="Validar tickets existentes sin usar IA")
    p.add_argument("--force", action="store_true", help="Regenerar tickets completos existentes")
    args = p.parse_args()
    if not (1 <= args.limit <= 150) or args.turns < 2 or args.timeout < 60:
        p.error("--limit entre 1 y 150; --turns >= 2; --timeout >= 60")

    root = Path(__file__).resolve().parent
    selection = root / "resultados/seleccion_15.json"
    if not selection.exists():
        raise SystemExit("Ejecuta primero: python analizar_alertas.py")
    casos = leer_json(selection).get("casos", [])[:args.limit]
    if not casos:
        raise SystemExit("La seleccion no contiene casos")
    if len({c["alert_id"] for c in casos}) != len(casos):
        raise SystemExit("ERROR: IDs duplicados en la seleccion")

    print(f"Lote: {len(casos)} alertas | Modelo: {args.model} | Turnos: {args.turns}")
    for case in casos:
        print(f" - {case['alert_id']} | {case.get('producto')} | {case.get('runbook')}")
    if args.dry_run:
        print("Modo simulacion: no se utiliza IA.")
        return

    try:
        import jsonschema  # noqa: F401
    except ImportError:
        raise SystemExit("Instala: python -m pip install jsonschema")
    schema = leer_json(root / "01_contexto/ticket_salida.schema.json")
    agent = root / "agente_soc_dcc_v2.py"
    if not agent.exists() and not args.verify_only:
        raise SystemExit("Falta agente_soc_dcc_v2.py junto al generador")
    if not args.verify_only and not os.getenv("DCC_API_KEY"):
        raise SystemExit("DCC_API_KEY no esta configurada en Secrets de Codespaces")
    base = os.getenv("SOC_API_URL", "http://127.0.0.1:8000")
    if not args.verify_only and not api_disponible(base):
        raise SystemExit("API Deloitte desconectada. Inicia uvicorn en puerto 8000")

    tickets_dir = root / "resultados/tickets"
    incomplete_dir = root / "resultados/incompletos"
    logs_dir = root / "resultados/logs"
    for folder in (tickets_dir, incomplete_dir, logs_dir):
        folder.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(LLM_PROVIDER="dcc", DCC_MODEL=args.model, SOC_MAX_TURNS=str(args.turns))

    rows = []
    for i, case in enumerate(casos, 1):
        aid = case["alert_id"]
        output = tickets_dir / f"{aid}.json"
        bad_path = incomplete_dir / f"{aid}.json"
        record = {"alert_id": aid, "producto": case.get("producto", ""),
                  "runbook": case.get("runbook", ""), "estado": "", "verdict": "",
                  "severity": "", "confidence": "", "triage_seconds": "",
                  "archivo": str(output.relative_to(root)), "detalle": ""}
        print(f"[{i}/{len(casos)}] {aid}", flush=True)

        if output.exists() and not args.force:
            try:
                ticket = validar_completo(output, aid, schema)
                record.update(estado="reutilizado_completo", verdict=ticket["verdict"],
                              severity=ticket["severity"], confidence=ticket["confidence"],
                              triage_seconds=ticket["triage_seconds"])
                rows.append(record)
                guardar_metricas(root, rows)
                print("  Ticket completo existente; sin repetir consulta de IA.")
                continue
            except Exception as exc:
                print(f"  Ticket existente incompleto: {exc}")
                if not args.verify_only:
                    output.replace(bad_path)

        if args.verify_only:
            record.update(estado="faltante_o_incompleto", detalle="No existe ticket completo")
            rows.append(record)
            continue

        if not api_disponible(base):
            record.update(estado="api_no_disponible", detalle="API SOC ya no responde en puerto 8000")
            rows.append(record)
            print("  API desconectada: se interrumpe el lote para evitar fallos en cascada.")
            break

        # Si se obliga a rehacer un ticket existente, guarda una copia primero.
        backup = root / "resultados/respaldo_tickets" / f"{aid}.json"
        if args.force and output.exists():
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(output, backup)
        output.unlink(missing_ok=True)
        env["SOC_OUTPUT_PATH"] = str(output)  # 1 alerta = 1 fichero DIRECTAMENTE
        log = logs_dir / f"{aid}.log"
        code, timed_out, elapsed = ejecutar_agente(agent, aid, output, log, env, args.timeout)
        record["triage_seconds"] = elapsed
        if timed_out:
            record.update(estado="timeout", detalle="Tiempo maximo excedido; revisar log")
        elif code != 0:
            record.update(estado="error_ejecucion", detalle=f"Codigo {code}; revisar {log.name}")
        elif not output.exists():
            record.update(estado="sin_json", detalle="El agente no genero el archivo esperado")
        else:
            try:
                ticket = validar_completo(output, aid, schema)
                record.update(estado="completo_pendiente_revision_humana", verdict=ticket["verdict"],
                              severity=ticket["severity"], confidence=ticket["confidence"],
                              triage_seconds=ticket["triage_seconds"], detalle="Estructura y campos presentes")
                bad_path.unlink(missing_ok=True)
            except Exception as exc:
                record.update(estado="incompleto", detalle=str(exc)[:300])
        if record["estado"] not in {"completo_pendiente_revision_humana", "reutilizado_completo"} and output.exists():
            # Conservar salidas parciales sin confundirlas con tickets completos
            output.replace(bad_path)
            record["archivo"] = str(bad_path.relative_to(root))
        # Nunca perder un ticket previo válido por un reintento que falla.
        if args.force and backup.exists() and record["estado"] not in {
            "completo_pendiente_revision_humana", "reutilizado_completo"
        }:
            try:
                old = validar_completo(backup, aid, schema)
                shutil.copy2(backup, output)
                record.update(estado="restaurado_completo_previo", verdict=old["verdict"],
                              severity=old["severity"], confidence=old["confidence"],
                              archivo=str(output.relative_to(root)),
                              detalle="Nueva ejecucion fallo; se conserva ticket anterior validado")
            except Exception:
                pass

        print(f"  -> {record['estado']}: {record['detalle']}", flush=True)
        rows.append(record)
        guardar_metricas(root, rows)

    guardar_metricas(root, rows)
    successes = [r for r in rows if r["estado"] in
                 {"completo_pendiente_revision_humana", "reutilizado_completo", "restaurado_completo_previo"}]
    print(f"\nRESULTADO: {len(successes)} / {len(casos)} tickets JSON completos (estructuralmente).")
    print(f"Carpeta: {tickets_dir}")
    print(f"Metricas: {root / 'resultados/metricas_tickets.csv'}")
    print("La veracidad de evidencias y los veredictos requieren revision humana.")
    print("No se han ejecutado acciones de contencion.")


if __name__ == "__main__":
    main()
