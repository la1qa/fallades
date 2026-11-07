#!/usr/bin/env python3
"""Inventario y pretriaje determinista de TODAS las alertas Tarvia (sin LLM).

Ejemplo: python analizar_alertas.py --limit-tickets 15
No asigna veredictos, no ejecuta contención y no usa claves de API.
"""
from __future__ import annotations

import argparse
import csv
import json
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SEVERIDADES = ('informational', 'low', 'medium', 'high', 'critical')
MATRIZ = {
    'informational': ('informational', 'informational', 'low', 'low'),
    'low':           ('informational', 'low', 'low', 'medium'),
    'medium':        ('low', 'medium', 'medium', 'high'),
    'high':          ('medium', 'high', 'high', 'critical'),
    'critical':      ('high', 'critical', 'critical', 'critical'),
}
CRIT = {'baja': 0, 'media': 1, 'alta': 2, 'crítica': 3, 'critica': 3}
MUESTRA = '03_alertas/alertas_muestra_desarrollo.jsonl'
COMPLETO = '03_alertas/alertas.jsonl'


def leer_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f'Falta {path}; ejecuta desde DTT-UAB-The-Hack o usa --root')
    with path.open(encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def leer_csv(path: Path) -> list[dict]:
    with path.open(encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))


def tiempo(iso: str) -> float:
    return datetime.fromisoformat(iso.replace('Z', '+00:00')).astimezone(timezone.utc).timestamp()


def elementos(entities: dict, clave: str) -> list:
    value = entities.get(clave) or []
    return value if isinstance(value, list) else [value]


def entidades(alerta: dict) -> dict[str, list[str]]:
    e = alerta.get('entities') or {}
    result: dict[str, set[str]] = defaultdict(set)
    for item in elementos(e, 'hosts'):
        value = (item.get('hostname') if isinstance(item, dict) else item)
        if value:
            result['host'].add(str(value).lower())
    for item in elementos(e, 'users'):
        value = (item.get('upn') or item.get('username') if isinstance(item, dict) else item)
        if value:
            result['user'].add(str(value).lower())
    for item in elementos(e, 'ips'):
        if isinstance(item, str) and item:
            result['ip'].add(item.lower())  # IP origen, NO implica activo afectado
    for item in elementos(e, 'domains'):
        value = (item.get('domain') if isinstance(item, dict) else item)
        if value:
            result['domain'].add(str(value).lower())
    for item in elementos(e, 'urls'):
        if isinstance(item, str):
            parsed = urlsplit(item)
            if parsed.path and parsed.path != '/':
                result['web_path'].add(parsed.path.lower())
    for item in alerta.get('related_events') or []:
        if item:
            result['event'].add(str(item).lower())
    return {k: sorted(v) for k, v in result.items()}


def cargar_contexto(root: Path):
    assets = {}
    for a in leer_csv(root / '02_inventario/activos.csv'):
        if a.get('hostname'):
            assets[a['hostname'].lower()] = a
    users = {}
    for u in leer_csv(root / '02_inventario/usuarios.csv'):
        for k in ('upn', 'username'):
            if u.get(k):
                users[u[k].lower()] = u
    return assets, users


def contexto(alerta: dict, features: dict[str, list[str]], assets: dict, users: dict) -> dict:
    # Un IP de origen o una URL pública NO identifican un servidor interno comprometido.
    conocidos = [assets[h] for h in features.get('host', []) if h in assets]
    cr = [(CRIT[x.get('criticality', '').lower()], x) for x in conocidos
          if x.get('criticality', '').lower() in CRIT]
    base = MATRIZ.get(alerta.get('severity'), (None,) * 4)[max(x for x, _ in cr)] if cr else None
    privilegiados = [u for k in features.get('user', []) if (u := users.get(k)) and
                     (u.get('vip', '').lower() == 'true' or u.get('privileged', '').lower() == 'true')]
    return {
        'activos_resueltos': sorted({a['hostname'] for a in conocidos}),
        'criticidad_maxima': ['Baja', 'Media', 'Alta', 'Crítica'][max(x for x, _ in cr)] if cr else '',
        'severidad_base_matriz': base or '',
        'identidades_vip_privilegiadas': sorted({u.get('upn', u.get('username', '')) for u in privilegiados}),
    }


def indicadores_proximos(alertas: list[dict], feats: list[dict], tiempos: list[float]):
    """Contadores orientativos; una coincidencia NO confirma un incidente."""
    index: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    kinds = ('host', 'user', 'ip', 'domain', 'event', 'web_path')
    for i, feat in enumerate(feats):
        for kind in kinds:
            for value in feat.get(kind, []):
                index[(kind, value)].append((tiempos[i], i))
    times_index = {}
    for key, vals in index.items():
        vals.sort()
        times_index[key] = [v[0] for v in vals]
    out = []
    for i, feat in enumerate(feats):
        ids = set()
        campaign = set()
        for kind in kinds:
            for value in feat.get(kind, []):
                key = (kind, value)
                vals = index[key]
                ts = times_index[key]
                lo = bisect_left(ts, tiempos[i] - 86400)
                hi = bisect_right(ts, tiempos[i] + 86400)
                # Nunca usar solamente una ruta web para afirmar 'mismo incidente'.
                target = campaign if kind == 'web_path' else ids
                for j in range(lo, hi):
                    if vals[j][1] != i:
                        target.add(vals[j][1])
        out.append((len(ids), len(campaign)))
    return out


def elegir_15(alertas: list[dict], cantidad: int) -> list[dict]:
    """Selección determinista; cubre runbooks, productos y severidades de la muestra.

    No es un muestreo estadístico representativo ni etiquetas de verdad.
    """
    ordered = sorted(alertas, key=lambda a: (a['created_at'], a['alert_id']))
    selected, used = [], set()
    def add(a):
        if a['alert_id'] not in used and len(selected) < cantidad:
            selected.append(a)
            used.add(a['alert_id'])
    # 1. Un caso por runbook, prefiriendo las severidades altas para probar criterios.
    by_runbook = defaultdict(list)
    for a in ordered:
        by_runbook[a.get('runbook', 'SIN_RUNBOOK')].append(a)
    for runbook in sorted(by_runbook):
        add(sorted(by_runbook[runbook], key=lambda a: (-SEVERIDADES.index(a.get('severity','low')), a['created_at'], a['alert_id']))[0])
    # 2. Garantizar un control conocido de actividad potencialmente autorizada (SCCM).
    for a in ordered:
        procesos = a.get('entities', {}).get('processes') or []
        if a.get('rule_id') == 'UC-EDR-002' and any(isinstance(pr, dict) and 'ccmexec' in str(pr.get('parent','')).lower() for pr in procesos):
            add(a)
            break
    # 3. Cobertura de productos que todavía no están representados.
    by_product = defaultdict(list)
    for a in ordered:
        by_product[a.get('source_product', '?')].append(a)
    for product in sorted(by_product, key=lambda p: (len(by_product[p]), p)):
        if not any(a['source_product'] == product for a in selected):
            for a in sorted(by_product[product], key=lambda a: (-SEVERIDADES.index(a['severity']), a['created_at'])):
                if a['alert_id'] not in used:
                    add(a)
                    break
    # 4. Completar diversidad por regla y severidad, sin duplicar casos.
    for a in sorted(ordered, key=lambda a: (
        sum(x['rule_id'] == a['rule_id'] for x in selected),
        sum(x['severity'] == a['severity'] for x in selected),
        -SEVERIDADES.index(a['severity']), a['created_at'], a['alert_id'])):
        add(a)
        if len(selected) == cantidad:
            break
    return selected


def main():
    p = argparse.ArgumentParser(description='Analizar 11.061 alertas sin gastar llamadas a IA y seleccionar 15')
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--output', type=Path, default=Path('resultados'))
    p.add_argument('--limit-tickets', type=int, default=15)
    p.add_argument('--pool', choices=['muestra', 'todas'], default='muestra', help='De dónde seleccionar los 15 tickets')
    args = p.parse_args()
    if args.limit_tickets < 1:
        p.error('--limit-tickets debe ser positivo')
    root = args.root.resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    output.mkdir(parents=True, exist_ok=True)
    alertas = leer_jsonl(root / COMPLETO)
    muestra = leer_jsonl(root / MUESTRA)
    assets, users = cargar_contexto(root)
    fs = [entidades(a) for a in alertas]
    ctx = [contexto(a, f, assets, users) for a, f in zip(alertas, fs)]
    ts = [tiempo(a['created_at']) for a in alertas]
    relacion = indicadores_proximos(alertas, fs, ts)
    csv_path = output / 'catalogo_alertas.csv'
    fields = ['alert_id', 'fecha_utc', 'producto', 'runbook', 'regla', 'severidad_regla',
              'criticidad_cmdb', 'severidad_base_matriz', 'activos_confirmados_en_cmdb',
              'identidades_vip_privilegiadas', 'eventos_relacionados',
              'posibles_relaciones_entidad_24h', 'misma_ruta_web_24h', 'observacion']
    with csv_path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fields)
        writer.writeheader()
        for a, c, r in zip(alertas, ctx, relacion):
            writer.writerow({
                'alert_id': a['alert_id'], 'fecha_utc': a['created_at'],
                'producto': a.get('source_product', ''), 'runbook': a.get('runbook',''),
                'regla': a.get('rule_id', ''), 'severidad_regla': a.get('severity',''),
                'criticidad_cmdb': c['criticidad_maxima'],
                'severidad_base_matriz': c['severidad_base_matriz'],
                'activos_confirmados_en_cmdb': '; '.join(c['activos_resueltos']),
                'identidades_vip_privilegiadas': '; '.join(c['identidades_vip_privilegiadas']),
                'eventos_relacionados': len(a.get('related_events') or []),
                'posibles_relaciones_entidad_24h': r[0], 'misma_ruta_web_24h': r[1],
                'observacion': ('Severidad base pendiente: no hay activo resuelto en CMDB.' if not c['severidad_base_matriz']
                                else 'Severidad BASE: verificar ajustes +1/-1 y evidencia antes de decidir.'),
            })
    pool = muestra if args.pool == 'muestra' else alertas
    chosen = elegir_15(pool, min(args.limit_tickets, len(pool)))
    seleccion = {
        'origen': args.pool,
        'nota': 'Selección para pruebas, no etiquetas de verdad. No confirma ningún incidente.',
        'alert_ids': [a['alert_id'] for a in chosen],
        'casos': [{'alert_id': a['alert_id'], 'producto': a['source_product'],
                   'runbook': a.get('runbook'), 'severity_regla': a['severity'],
                   'regla': a['rule_id']} for a in chosen],
    }
    (output / 'seleccion_15.json').write_text(json.dumps(seleccion, indent=2, ensure_ascii=False), encoding='utf-8')
    resumen = {
        'total_alertas': len(alertas), 'alertas_muestra': len(muestra),
        'por_producto': dict(Counter(a['source_product'] for a in alertas)),
        'por_runbook': dict(Counter(a.get('runbook','') for a in alertas)),
        'por_severidad_regla': dict(Counter(a['severity'] for a in alertas)),
        'base_matriz_calculable': sum(bool(c['severidad_base_matriz']) for c in ctx),
        'base_matriz_pendiente': sum(not c['severidad_base_matriz'] for c in ctx),
        'limitaciones': [
            'Este pretriaje NO emite veredictos ni severidad FINAL; requiere investigación con logs e inteligencia.',
            'Una IP externa es un origen, no un activo comprometido; CMDB solo resuelve hosts explícitos.',
            'Coincidencias de entidades o rutas durante ±24h son pistas, NO grupos de incidentes confirmados.',
            'No se comprueba el histórico de logs ni la autorización de cambios en esta fase.',
            'La muestra de 150 no contiene critical ni los runbooks RB-08 y RB-10.',
        ],
    }
    (output / 'resumen_dataset.json').write_text(json.dumps(resumen, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'[OK] {len(alertas):,} alertas catalogadas -> {csv_path}')
    print(f'[OK] Resumen -> {output / "resumen_dataset.json"}')
    print(f'[OK] {len(chosen)} alertas seleccionadas -> {output / "seleccion_15.json"}')
    print('Seleccionadas:', ', '.join(seleccion['alert_ids']))
    print('NOTA: análisis determinista, sin tickets de IA ni acciones de contención.')


if __name__ == '__main__':
    main()
