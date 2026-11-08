#!/usr/bin/env python3
"""Tarvia SOC: análisis y agrupación de TODAS las alertas sin LLM ni contención.

No necesita la API Deloitte: lee 03_alertas/alertas.jsonl.
Agrupa propuestas de incidentes por identificadores sólidos y patrones por campaña
separadamente. No convierte coincidencias heurísticas en incidentes confirmados.

  python analizar_agrupar_todas.py --actualizar
  python analizar_agrupar_todas.py --estado
  python analizar_agrupar_todas.py --actualizar --forzar
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / '03_alertas' / 'alertas.jsonl'
TICKET_DIR = ROOT / 'resultados' / 'tickets'
OUT = ROOT / 'resultados' / 'analisis_global'
VERSION = 'global-2026-11-v2'
SEVERITY_ORDER = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
PRIORITY = {'informational': 5, 'low': 20, 'medium': 45, 'high': 75, 'critical': 95}
# Cada episodio se limita por el primer evento; sin unir cadenas mediante A-B-C.
MAX_GROUP = 120
INCIDENT_WINDOW = 6 * 3600
MAX_ALERTS_PER_KEY = 150  # Solo para huellas de incidente; claves comunes no justifican fusión.


def normalized(v):
    return str(v).strip().lower() if v is not None else ''


def as_items(v):
    if v is None: return []
    return v if isinstance(v, list) else [v]


def parse_epoch(ts):
    d = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
    if d.tzinfo is None: raise ValueError('fecha sin zona UTC')
    return int(d.timestamp())


def identifier(prefix, values):
    digest = hashlib.sha1((prefix + '|' + '|'.join(values)).encode('utf-8')).hexdigest()[:12].upper()
    return prefix + '-' + digest


def features(a):
    """Etiquetas con roles. No asumimos que cualquier IP sea activo interno."""
    e = a.get('entities') or {}
    f = defaultdict(set)
    for x in as_items(e.get('users')):
        if isinstance(x, dict): v = x.get('upn') or x.get('username')
        else: v = x
        v = normalized(v)
        if v and not v.startswith('('): f['user'].add(v)
    for x in as_items(e.get('hosts')):
        if isinstance(x, dict):
            hn = normalized(x.get('hostname'))
            ip = normalized(x.get('ip'))
            if hn: f['host'].add(hn)
            if ip: f['dest_ip'].add(ip)
        else:
            hn = normalized(x)
            if hn: f['host'].add(hn)
    # 'ips' no garantiza el papel exacto: se conserva como IP observada, no se llama origen.
    for x in as_items(e.get('ips')):
        if isinstance(x, str) and x.strip(): f['observed_ip'].add(normalized(x))
    for x in as_items(e.get('files')):
        val = normalized((x.get('sha256') or x.get('hash')) if isinstance(x, dict) else x)
        if re.fullmatch(r'[a-f0-9]{64}', val): f['sha256'].add(val)
    for x in as_items(e.get('domains')):
        v = normalized(x.get('domain') if isinstance(x, dict) else x)
        if v: f['domain'].add(v)
    for x in as_items(e.get('urls')):
        if isinstance(x, str):
            path = urlsplit(x).path.lower().rstrip('/')
            if path: f['web_path'].add(path)
    for x in as_items(e.get('customers')):
        v = normalized(x.get('customer_id') if isinstance(x, dict) else x)
        if v: f['customer'].add(v)
    for x in as_items(a.get('related_events')):
        v = normalized(x)
        if v: f['event_id'].add(v)
    cloud = e.get('cloud') or {}
    if isinstance(cloud, dict):
        v = normalized(cloud.get('principal') or cloud.get('identity'))
        if v: f['cloud_identity'].add(v)
    sess = e.get('ai_session') or {}
    if isinstance(sess, dict):
        v = normalized(sess.get('session_id') or sess.get('id'))
    else: v = normalized(sess)
    if v: f['session'].add(v)
    return dict(f)


def read_alerts():
    records, errors, ids = [], [], set()
    with SOURCE.open(encoding='utf-8') as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip(): continue
            try:
                a = json.loads(line)
                aid = a['alert_id']
                if aid in ids: raise ValueError('alert_id duplicado')
                ts = parse_epoch(a['created_at'])
                ids.add(aid)
                r = {
                    'id': aid, 'ts': ts, 'date': a['created_at'],
                    'source': str(a.get('source_product') or ''),
                    'rule': str(a.get('rule_id') or ''),
                    'rule_name': str(a.get('rule_name') or ''),
                    'runbook': str(a.get('runbook') or ''),
                    'severity': str(a.get('severity') or 'informational').lower(),
                    'features': features(a),
                }
                records.append(r)
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as ex:
                errors.append({'line': line_no, 'error': str(ex)})
    records.sort(key=lambda r:(r['ts'],r['id']))
    return records, errors


def ticket_ids():
    # Nombres de JSON existentes: la validación humana va por separado.
    return {p.stem for p in TICKET_DIR.glob('ALR-*.json')} if TICKET_DIR.exists() else set()


def make_bucket_index(records):
    """Índice invertido O(alertas * entidades), sin pares N x N."""
    i = defaultdict(list)
    for r in records:
        f = r['features']
        for event_id in f.get('event_id', ()):
            i[('event',event_id)].append(r)
        for session in f.get('session', ()):
            i[('session',session)].append(r)
        for user in f.get('user', ()):
            for host in f.get('host', ()):
                i[('user_host',user,host)].append(r)
            for ip in f.get('observed_ip', ()):
                i[('user_ip',user,ip)].append(r)
        for host in f.get('host', ()):
            for sha in f.get('sha256', ()):
                i[('host_sha',host,sha)].append(r)
            for ip in f.get('observed_ip', ()):
                i[('host_ip',host,ip)].append(r)
        for identity in f.get('cloud_identity', ()):
            for ip in f.get('observed_ip', ()):
                i[('cloud_ip',identity,ip)].append(r)
    return i


def split_episodes(members, window, max_items=MAX_GROUP):
    """Ventana desde la primera alerta; prohíbe uniones en cadena indefinidas."""
    groups, current, start = [], [], None
    for r in sorted(members, key=lambda x:(x['ts'],x['id'])):
        if current and (r['ts'] - start > window or len(current) >= max_items):
            groups.append(current)
            current, start = [], None
        if not current: start = r['ts']
        current.append(r)
    if current: groups.append(current)
    return groups


def incident_proposals(records):
    index = make_bucket_index(records)
    candidates = []
    ignored_keys = 0
    windows = {'event': 24*3600, 'session': 12*3600,
               'user_host': INCIDENT_WINDOW, 'user_ip': INCIDENT_WINDOW,
               'host_sha': INCIDENT_WINDOW, 'host_ip': INCIDENT_WINDOW,
               'cloud_ip': INCIDENT_WINDOW}
    weights = {'event':100, 'session':95, 'host_sha':88,
               'user_host':85, 'user_ip':82, 'cloud_ip':80, 'host_ip':70}
    for key, rows in index.items():
        kind = key[0]
        if len(rows) < 2: continue
        # Claves recurrentes no son un identificador exclusivo.
        if len(rows) > MAX_ALERTS_PER_KEY and kind not in ('event','session'):
            ignored_keys += 1
            continue
        for episode in split_episodes(rows, windows[kind]):
            if len(episode) < 2: continue
            if kind == 'host_ip' and len({r['source'] for r in episode}) < 2:
                continue
            # Eventos con exactamente la misma regla/host también requieren revisión;
            # clasificamos como potencial, no como ataque confirmado.
            ids = sorted({r['id'] for r in episode})
            if len(ids) < 2: continue
            candidates.append({
                'id':identifier('INC', [kind, *key[1:], *ids]),
                'tipo':'incidente_candidato',
                'criterio':kind, 'clave':list(key[1:]),
                'puntuacion_regla':weights[kind],
                'alert_ids':ids, 'n_alertas':len(ids),
                'inicio':min(r['date'] for r in episode), 'fin':max(r['date'] for r in episode),
                'max_severidad':max((r['severity'] for r in episode),key=lambda s:SEVERITY_ORDER.get(s,-1)),
                'fuentes':sorted({r['source'] for r in episode}),
                'estado':'pendiente_revision_humana',
            })
    # Las alertas pueden tener varias correlaciones válidas: para presentación
    # asignamos solo una propuesta principal y registramos las otras como solapamientos.
    candidates.sort(key=lambda c:(-c['puntuacion_regla'],-c['n_alertas'],c['id']))
    assigned, primary, overlaps = set(), [], []
    for c in candidates:
        free = [aid for aid in c['alert_ids'] if aid not in assigned]
        if len(free) >= 2:
            c = dict(c, alert_ids=free, n_alertas=len(free))
            primary.append(c)
            assigned.update(free)
        elif len(c['alert_ids']) >= 2 and len(overlaps)<500:
            # Referencias cruzadas no implican una fusión automática.
            overlaps.append({'criterio':c['criterio'],'alert_ids':c['alert_ids'][:20]})
    primary.sort(key=lambda c:(-SEVERITY_ORDER.get(c['max_severidad'],-1),-c['n_alertas'],c['id']))
    return primary, assigned, ignored_keys, overlaps


def campaigns(records):
    """Patrones por intervalo. Campaña ≠ mismo incidente ni veredicto malicioso."""
    buckets = defaultdict(list)
    for r in records:
        kind, f, src, rule = None, r['features'],r['source'].upper(),r['rule']
        # Solo huellas de amenazas/patrones; no usar únicamente el runbook.
        if src == 'WAF':
            for path in f.get('web_path', ()):
                buckets[('waf_path', rule, path, r['ts']//(6*3600))].append(r)
        elif src in ('EMAIL_GW','EMAIL'):
            for domain in f.get('domain', ()):
                buckets[('email_domain',rule,domain,r['ts']//(6*3600))].append(r)
        elif src == 'EDR':
            for sha in f.get('sha256', ()):
                buckets[('edr_hash',rule,sha,r['ts']//(24*3600))].append(r)
        elif src in ('DNS','PROXY'):
            for domain in f.get('domain', ()):
                buckets[('network_domain',rule,domain,r['ts']//(6*3600))].append(r)
    result = []
    for key, rows in buckets.items():
        ids = sorted({r['id'] for r in rows})
        if len(ids) < 3: continue
        result.append({
            'id':identifier('CAM', [*map(str,key), *ids]),
            'tipo':'patron_campana', 'criterio':key[0], 'firma':str(key[2]),
            'regla':str(key[1]), 'alert_ids':ids, 'n_alertas':len(ids),
            'inicio':min(r['date'] for r in rows), 'fin':max(r['date'] for r in rows),
            'fuentes':sorted({r['source'] for r in rows}),
            'estado':'patron_no_confirmado',
        })
    result.sort(key=lambda r:(-r['n_alertas'],r['id']))
    return result


def ticket_fingerprint(tickets):
    return hashlib.sha1('\n'.join(sorted(tickets)).encode('utf-8')).hexdigest()


def refresh_ticket_columns(tickets):
    """Actualizar sólo cobertura N1: no recalcular correlaciones."""
    for name in ('alertas_analizadas.csv', 'prioridad_revision.csv'):
        path = OUT / name
        if not path.exists(): continue
        with path.open(encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            columns = reader.fieldnames
            rows = list(reader)
        if not columns: continue
        for r in rows:
            r['tiene_ticket_al_generar'] = 'si' if r['alert_id'] in tickets else 'no'
        save_csv(path, columns, rows)


def save_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp = path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
    tmp.replace(path)


def save_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp = path.with_suffix(path.suffix+'.tmp')
    with tmp.open('w',encoding='utf-8-sig',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=fieldnames,extrasaction='ignore');wr.writeheader();wr.writerows(rows)
    tmp.replace(path)


def source_signature():
    st=SOURCE.stat()
    # Cambios en tickets NO obligan a recalcular alertas; solo su etiqueta de cobertura.
    return f'{VERSION}:{st.st_size}:{st.st_mtime_ns}'


def run(force=False):
    started=time.perf_counter()
    OUT.mkdir(parents=True, exist_ok=True)
    old=OUT/'resumen_general.json'
    signature=source_signature()
    previous={}
    if old.exists():
        try:previous=json.loads(old.read_text(encoding='utf-8'))
        except (ValueError,OSError):pass
    # Los tickets pueden aumentar mucho: las agrupaciones independientes de N1 se
    # reutilizan; no recalculamos 11.061 alertas por cada nuevo ticket.
    if not force and previous.get('source_signature')==signature and (OUT/'alertas_analizadas.csv').exists():
        tickets=ticket_ids()
        fingerprint=ticket_fingerprint(tickets)
        if fingerprint != previous.get('ticket_id_fingerprint'):
            refresh_ticket_columns(tickets)
        previous['tickets_disponibles']=len(tickets)
        previous['ticket_id_fingerprint']=fingerprint
        previous['reutilizado_cache']=True
        previous['segundos_ultima_ejecucion']=round(time.perf_counter()-started,3)
        save_json(old,previous)
        print('Agrupación existente reutilizada: no se recalculan las 11.061 alertas.')
        print(json.dumps({k:previous.get(k) for k in ('total_alertas','incidentes_candidatos','campanas_patron','alertas_sin_incidente','tickets_disponibles','segundos_ultima_ejecucion')},ensure_ascii=False))
        return previous
    recs, errors=read_alerts()
    groups, grouped, skipped, overlaps=incident_proposals(recs)
    camps=campaigns(recs)
    campaign_ids={aid for c in camps for aid in c['alert_ids']}
    tickets=ticket_ids()
    pmap={aid:c['id'] for c in groups for aid in c['alert_ids']}
    cmap={}
    for c in camps:
        for aid in c['alert_ids']:
            cmap.setdefault(aid,c['id'])
    counts_severity=Counter(r['severity'] for r in recs)
    counts_source=Counter(r['source'] for r in recs)
    counts_rules=Counter((r['rule'],r['rule_name']) for r in recs)
    raw_rows=[]
    for r in recs:
        priority=PRIORITY.get(r['severity'],20)
        if r['id'] in pmap: priority=min(100,priority+10)
        raw_rows.append({
            'alert_id':r['id'],'created_at':r['date'],'source_product':r['source'],
            'rule_id':r['rule'],'rule_name':r['rule_name'],'runbook':r['runbook'],
            'severity_original':r['severity'],'prioridad_pretriaje':priority,
            'incidente_candidato_id':pmap.get(r['id'],''),
            'campana_patron_id':cmap.get(r['id'],''),
            'tiene_ticket_al_generar':'si' if r['id'] in tickets else 'no',
            'estado':'incidente_candidato' if r['id'] in pmap else 'patron_campana' if r['id'] in campaign_ids else 'sin_relacion_fuerte',
        })
    cols=list(raw_rows[0]) if raw_rows else ['alert_id']
    save_csv(OUT/'alertas_analizadas.csv',cols,raw_rows)
    save_csv(OUT/'prioridad_revision.csv',cols,sorted(raw_rows,key=lambda r:(-r['prioridad_pretriaje'],r['created_at'],r['alert_id'])))
    save_json(OUT/'incidentes_candidatos.json',groups)
    save_json(OUT/'campanas_patron.json',camps)
    save_json(OUT/'solapamientos_para_revision.json',overlaps)
    save_csv(OUT/'estadisticas_por_fuente.csv',['fuente','alertas'],[{'fuente':src,'alertas':n} for src,n in counts_source.most_common()])
    save_csv(OUT/'estadisticas_por_regla.csv',['regla','nombre','alertas'],[{'regla':k[0],'nombre':k[1],'alertas':n} for k,n in counts_rules.most_common()])
    summary={
        'version':VERSION,'source_signature':signature,
        'generado_utc':datetime.now(timezone.utc).isoformat(),
        'total_alertas':len(recs),'lineas_invalidas':len(errors),
        'detalle_lineas_invalidas':errors[:30],
        'tickets_disponibles':len(tickets),
        'ticket_id_fingerprint':ticket_fingerprint(tickets),
        'incidentes_candidatos':len(groups),
        'alertas_en_incidentes_candidatos':len(grouped),
        'campanas_patron':len(camps),
        'alertas_en_campanas':len(campaign_ids),
        'alertas_sin_incidente':len(recs)-len(grouped),
        'alertas_sin_relacion_fuerte':len({r['id'] for r in recs}-grouped-campaign_ids),
        'claves_demasiado_comunes_ignoradas':skipped,
        'severidad_original':dict(counts_severity),
        'por_fuente':dict(counts_source),
        'segundos_ultima_ejecucion':round(time.perf_counter()-started,3),
        'reutilizado_cache':False,
        'advertencias':[
            'El sistema analiza metadatos de 03_alertas/alertas.jsonl, NO verifica todos los eventos de 04_logs.',
            'Agrupación y pretriaje deterministas: NO son veredictos SOC ni incidentes confirmados.',
            'Las campañas pueden solaparse con incidentes candidatos; no son una sola intrusión.',
            'La puntuación de prioridad no es una probabilidad; revisión humana imprescindible.',
            'La cobertura de tickets se actualiza con cada --actualizar, sin recalcular las agrupaciones.'
        ],
    }
    save_json(old,summary)
    print(json.dumps({k:summary[k] for k in ('total_alertas','lineas_invalidas','incidentes_candidatos','alertas_en_incidentes_candidatos','campanas_patron','alertas_en_campanas','alertas_sin_relacion_fuerte','tickets_disponibles','segundos_ultima_ejecucion')},indent=2,ensure_ascii=False))
    print(f'Archivos: {OUT.relative_to(ROOT)}')
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--actualizar',action='store_true',help='Analizar datos y crear resultados')
    group.add_argument('--estado',action='store_true',help='Mostrar estado guardado')
    parser.add_argument('--forzar',action='store_true',help='Recalcular aunque haya caché')
    args=parser.parse_args()
    if args.estado:
        path=OUT/'resumen_general.json'
        if not path.exists(): parser.error('No existe resumen: ejecuta --actualizar primero')
        print(path.read_text(encoding='utf-8'))
        return
    if not SOURCE.exists():parser.error(f'Falta {SOURCE}. Coloca el script en DTT-UAB-The-Hack')
    run(args.forzar)


if __name__=='__main__':main()
