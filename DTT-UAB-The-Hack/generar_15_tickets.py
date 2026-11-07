#!/usr/bin/env python3
"""Generación controlada de hasta 15 tickets N1 usando el agente DCC EXISTENTE.

Previo: python analizar_alertas.py
Prueba: python generar_15_tickets.py --dry-run
Ejemplo: python generar_15_tickets.py --limit 3
Lote: python generar_15_tickets.py --limit 15

- Un archivo JSON por alerta; validación de esquema e ID; resumen CSV.
- Reanuda sin recalcular tickets válidos (--force para rehacer).
- Conserva y restaura ticket_generado.json, que el agente actual sobrescribe.
- Solo realiza consultas de lectura; no ejecuta contención.
- Requiere API SOC activa en localhost:8000 y DCC_API_KEY en Codespaces.
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
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen


def ahora():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def atomic_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.part')
    temporary.write_bytes(data)
    temporary.replace(path)


def cargar_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def verificar_ticket(path: Path, alert_id: str, schema: dict) -> dict:
    from jsonschema import validate
    ticket = cargar_json(path)
    validate(instance=ticket, schema=schema)
    if alert_id not in ticket.get('alert_ids', []):
        raise ValueError('El ticket NO contiene el ID de la alerta investigada')
    if ticket.get('executed_actions'):
        raise ValueError('Se detectaron acciones ejecutadas; el lote N1 no permite contención')
    if not ticket.get('evidence'):
        raise ValueError('Ticket sin evidencias; requiere revisión')
    return ticket


def comprobar_api(url: str):
    try:
        with urlopen(url.rstrip('/') + '/openapi.json', timeout=12) as r:
            if r.status != 200:
                raise RuntimeError(f'HTTP {r.status}')
    except Exception as exc:
        raise SystemExit(f'No se puede conectar con la API SOC en {url}: {exc}\n'
                         'Inicia primero uvicorn en otra terminal (puerto 8000).') from exc


def resumen_csv(carpeta: Path, casos: list[dict]):
    path = carpeta / 'metricas_tickets.csv'
    fields = ['alert_id', 'producto', 'runbook', 'severidad_regla', 'estado',
              'veredicto', 'severidad_final_llm', 'confianza', 'segundos', 'archivo', 'detalle']
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for a in casos:
            writer.writerow({k: a.get(k, '') for k in fields})
    return path


def investigar(agente: Path, aid: str, logfile: Path, env: dict, timeout_seconds: int) -> tuple[int | None, bool]:
    """Ejecuta una investigación; salidas a log; indica progreso incluso si el LLM tarda."""
    t0 = time.monotonic()
    print(f'  [IA] {aid} -> {logfile.name}', flush=True)
    with logfile.open('w', encoding='utf-8') as log:
        proc = subprocess.Popen([sys.executable, '-u', str(agente), aid],
                                cwd=str(agente.parent), env=env,
                                stdout=log, stderr=subprocess.STDOUT)
        try:
            while True:
                try:
                    code = proc.wait(timeout=15)
                    break
                except subprocess.TimeoutExpired:
                    secs = int(time.monotonic() - t0)
                    print(f'    Investigando... {secs}s (consultas en {logfile.name})', flush=True)
                    if secs >= timeout_seconds:
                        print(f'    [LÍMITE] {timeout_seconds}s; deteniendo investigación', flush=True)
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                        return proc.returncode, True
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            raise
    return code, False


def main():
    ap = argparse.ArgumentParser(description='Generar tickets IA a partir de seleccion_15.json')
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument('--seleccion', default='resultados/seleccion_15.json')
    ap.add_argument('--limit', type=int, default=15)
    ap.add_argument('--timeout', type=int, default=600, help='Segundos máximos por alerta')
    ap.add_argument('--model', default='ornith', help='Modelo de la UAB; alternativa nemotron')
    ap.add_argument('--force', action='store_true', help='Reinvestigar tickets válidos')
    ap.add_argument('--dry-run', action='store_true', help='Mostrar selección sin llamadas al modelo')
    args = ap.parse_args()
    if args.limit < 1 or args.timeout < 60:
        ap.error('--limit >= 1 y --timeout >= 60')
    root = args.root.resolve()
    select_path = Path(args.seleccion)
    if not select_path.is_absolute():
        select_path = root / select_path
    if not select_path.exists():
        raise SystemExit('Falta seleccion_15.json. Primero ejecuta: python analizar_alertas.py')
    seleccion = cargar_json(select_path)
    casos = seleccion['casos'][:args.limit]
    if not casos:
        raise SystemExit('La selección no contiene alertas')
    ids = [case['alert_id'] for case in casos]
    if len(ids) != len(set(ids)):
        raise SystemExit('La selección tiene IDs duplicados')
    print(f'Lote: {len(casos)} alertas; modelo={args.model}.')
    for c in casos:
        print(f" - {c['alert_id']} | {c['producto']} | {c['runbook']} | {c['severity_regla']}")
    if args.dry_run:
        print('Modo simulación: sin consultar la IA, sin generar tickets.')
        return
    if not os.getenv('DCC_API_KEY'):
        raise SystemExit('Falta el secreto DCC_API_KEY en Codespaces; no lo pegues en el código.')
    agente = root / 'agente_soc_dcc.py'
    if not agente.exists():
        raise SystemExit(f'No existe {agente}')
    try:
        import jsonschema  # noqa: F401
    except ImportError as exc:
        raise SystemExit('Instala: python -m pip install jsonschema openai-agents requests') from exc
    schema = cargar_json(root / '01_contexto/ticket_salida.schema.json')
    comprobar_api(os.environ.get('SOC_API_URL', 'http://127.0.0.1:8000'))
    outdir = root / 'resultados'
    ticketdir = outdir / 'tickets'
    logdir = outdir / 'logs'
    ticketdir.mkdir(parents=True, exist_ok=True)
    logdir.mkdir(parents=True, exist_ok=True)

    # El agente actual utiliza un único nombre de salida. Respaldo PERSISTENTE
    # para que no se pierda el primer ticket si el proceso se interrumpe.
    global_ticket = root / 'ticket_generado.json'
    backup = outdir / 'respaldo_ticket_original.json'
    if global_ticket.exists():
        # Respalda SIEMPRE la versión que existe al iniciar este lote.
        # En ejecuciones posteriores puede ser distinta del primer ticket.
        shutil.copy2(global_ticket, backup)
        print(f'Respaldo del ticket inicial: {backup}')
    elif backup.exists():
        print(f'Encontrado respaldo previo: {backup}')

    results = []
    env = os.environ.copy()
    env['LLM_PROVIDER'] = 'dcc'
    env['DCC_MODEL'] = args.model
    env['SOC_MAX_TURNS'] = env.get('SOC_MAX_TURNS', '12')
    try:
        for n, case in enumerate(casos, 1):
            aid = case['alert_id']
            output = ticketdir / (aid + '.json')
            record = {'alert_id': aid, 'producto': case['producto'],
                      'runbook': case.get('runbook', ''), 'severidad_regla': case['severity_regla'],
                      'estado': '', 'veredicto': '', 'severidad_final_llm': '',
                      'confianza': '', 'segundos': '', 'archivo': str(output.relative_to(root)), 'detalle': ''}
            print(f'[{n}/{len(casos)}] {aid}', flush=True)
            if output.exists() and not args.force:
                try:
                    ticket = verificar_ticket(output, aid, schema)
                    record.update(estado='reutilizado', veredicto=ticket['verdict'],
                                  severidad_final_llm=ticket['severity'],
                                  confianza=ticket['confidence'], segundos=ticket.get('triage_seconds', ''))
                    results.append(record)
                    resumen_csv(outdir, results)
                    print('  Ya existe y es válido; omitido.')
                    continue
                except Exception as exc:
                    print(f'  Ticket previo inválido, se regenerará: {exc}')
            if global_ticket.exists():
                global_ticket.unlink()  # evita confundir un JSON antiguo con un ticket nuevo
            logfile = logdir / (aid + '.log')
            t0 = time.monotonic()
            code, timed_out = investigar(agente, aid, logfile, env, args.timeout)
            record['segundos'] = round(time.monotonic() - t0, 2)
            if timed_out:
                record.update(estado='timeout', detalle=f'Excedidos {args.timeout}s; revisar log')
            elif code != 0:
                record.update(estado='error_ejecucion', detalle=f'Exit code={code}; revisar log')
            elif not global_ticket.is_file():
                record.update(estado='sin_ticket', detalle='El agente no generó ticket_generado.json')
            else:
                try:
                    ticket = verificar_ticket(global_ticket, aid, schema)
                    atomic_write(output, global_ticket.read_bytes())
                    record.update(estado='valido_pendiente_revision',
                                  veredicto=ticket['verdict'],
                                  severidad_final_llm=ticket['severity'],
                                  confianza=ticket['confidence'],
                                  segundos=ticket.get('triage_seconds', record['segundos']),
                                  detalle='Validación estructural correcta; falta verificación humana de veredicto')
                except Exception as exc:
                    record.update(estado='ticket_invalido', detalle=str(exc)[:350])
            results.append(record)
            resumen_csv(outdir, results)
            print(f"  RESULTADO: {record['estado']} {record['detalle']}", flush=True)
    except KeyboardInterrupt:
        print('\nInterrumpido; quedan guardados los tickets ya completados.')
    finally:
        if backup.exists():
            atomic_write(global_ticket, backup.read_bytes())
            print(f'Restaurado ticket_generado.json desde {backup.name}')
        print('Resumen:', resumen_csv(outdir, results))
        print('Válidos o reutilizados:', sum(r['estado'] in ('valido_pendiente_revision','reutilizado') for r in results),
              '/', len(casos))
    print('No se han ejecutado acciones de contención. Revisar calidad antes de producción.')


if __name__ == '__main__':
    main()
