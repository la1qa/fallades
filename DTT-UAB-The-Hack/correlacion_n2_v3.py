#!/usr/bin/env python3
"""Correlación N2 para Tarvia V3. Sin IA y sin alterar severidades N1.

Los grupos de analizar_agrupar_todas.py son HIPÓTESIS. Un +1 contextual
solo aparece tras confirmación manual con dos tickets y dos eventos
contrastados en 04_logs. No existe -1 de correlación.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

GRUPOS = Path('resultados/analisis_global/incidentes_candidatos.json')
REVISIONES = Path('resultados/v3/revisiones')
TICKETS_V3 = Path('resultados/v3/tickets')
TICKETS_V2 = Path('resultados/tickets')
NIVELES = ('informational', 'low', 'medium', 'high', 'critical')
VEREDICTOS = {'true_positive', 'benign_true_positive', 'false_positive', 'needs_more_info'}
FUENTES = {'waf','proxy','dns','edr_events','idp_signins','email','email_clicks',
           'firewall','vpn','ecom_auth','ecom_account','cloudtrail','sql_audit',
           'dlp','idp_audit','cicd_builds','ai_gateway','ad_events'}
ALIAS = {'edr':'edr_events', 'email_gw':'email', 'correo':'email',
         'ngfw':'firewall', 'idp':'idp_signins', 'ad':'ad_events',
         'cloud':'cloudtrail', 'inteligencia_tip':None, 'db_activo':None,
         'db_usuario':None, 'cambios_aprobados':None}


def leer_json(ruta: Path):
    return json.loads(ruta.read_text(encoding='utf-8'))


def guardar_json(ruta: Path, obj: dict):
    """Escritura atómica de un archivo nuevo o de evaluación (no N1)."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_name(ruta.name + '.part')
    temporal.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding='utf-8')
    temporal.replace(ruta)


@lru_cache(maxsize=8)
def _indice_grupos(ruta_str: str, mtime_ns: int, size: int):
    registros = leer_json(Path(ruta_str))
    if not isinstance(registros, list):
        raise ValueError('El archivo de grupos debe contener una lista JSON')
    por_alerta: dict[str, list] = {}
    por_id: dict[str, dict] = {}
    for grupo in registros:
        if not isinstance(grupo, dict) or not isinstance(grupo.get('alert_ids'), list):
            continue
        gid = str(grupo.get('id',''))
        if not gid or gid in por_id:
            continue
        por_id[gid] = grupo
        for aid in set(grupo['alert_ids']):
            if isinstance(aid, str):
                por_alerta.setdefault(aid, []).append(grupo)
    return por_alerta, por_id


def indice_grupos(root: Path):
    ruta = root / GRUPOS
    if not ruta.is_file():
        return {}, {}
    stat = ruta.stat()
    return _indice_grupos(str(ruta.resolve()), stat.st_mtime_ns, stat.st_size)


def grupos_alerta(root: Path, alert_id: str, max_grupos: int = 2):
    por_alerta, _ = indice_grupos(root)
    candidatos = por_alerta.get(alert_id, [])
    return sorted(candidatos,
                  key=lambda g: (-int(g.get('puntuacion_regla',0)), str(g['id'])))[:max_grupos]


def contexto_alerta(root: Path, alert_id: str) -> dict:
    """Resumen corto: 2 grupos y hasta 4 alertas relacionadas, sin llamadas a IA."""
    candidatos = []
    for grupo in grupos_alerta(root, alert_id):
        candidatos.append({
            'group_id': grupo['id'],
            'criterio_preliminar': str(grupo.get('criterio',''))[:60],
            'relacionadas': [aid for aid in grupo['alert_ids'] if aid != alert_id][:4],
            'ventana': [grupo.get('inicio'), grupo.get('fin')],
            'estado': 'hipotesis_no_confirmada',
        })
    return {'alerta_principal': alert_id, 'grupos_candidatos': candidatos,
            'advertencia': ('La coincidencia no prueba la misma intrusion. '
                            'No modificar severidad N1 ni fusionar alert_ids por esta lista.')}


def normalizar_veredicto(ticket: dict, alert_id: str) -> dict:
    """Validación en el núcleo V3; nunca inventa TP/FP ni cambia severidad.

    Solo convierte etiquetas NO válidas a needs_more_info y registra
    el motivo. Si la severidad es inválida, el esquema la rechazará.
    """
    t = dict(ticket)
    valor = str(t.get('verdict','')).strip().lower()
    if valor in VEREDICTOS:
        t['verdict'] = valor
    else:
        t['verdict'] = 'needs_more_info'
        try:
            confianza = float(t.get('confidence',0))
        except (ValueError, TypeError):
            confianza = 0
        t['confidence'] = min(max(0,confianza),0.25)
        preguntas = list(t.get('open_questions', []) or [])
        preguntas.append('Veredicto generado no permitido (' + repr(valor[:45]) +
                         '); hace falta validación humana y revisar las evidencias.')
        t['open_questions'] = preguntas
    return t


def ticket_ubicacion(root: Path, alert_id: str):
    for carpeta in (TICKETS_V3, TICKETS_V2):
        ruta = root / carpeta / f'{alert_id}.json'
        if ruta.is_file():
            try:
                ticket = leer_json(ruta)
                if alert_id in ticket.get('alert_ids', []):
                    return ruta
            except (OSError, ValueError):
                pass
    return None


def sha_json(ruta: Path):
    return hashlib.sha256(ruta.read_bytes()).hexdigest()


def firma_grupo(grupo: dict):
    parte = {'id':grupo.get('id'), 'alert_ids':sorted(set(grupo.get('alert_ids',[])))}
    return hashlib.sha256(json.dumps(parte, sort_keys=True).encode()).hexdigest()


def firma_tickets(root: Path, alert_ids: list[str]):
    firmas = {}
    for aid in sorted(set(alert_ids)):
        ruta = ticket_ubicacion(root, aid)
        if ruta is None:
            return None
        firmas[aid] = sha_json(ruta)
    return firmas


def ruta_log(root: Path, source: str):
    fuente = str(source or '').strip().lower()
    if re.fullmatch(r'edr-\d+', fuente):
        fuente = 'edr'
    elif re.fullmatch(r'fw-\d+', fuente):
        fuente = 'firewall'
    nombre = ALIAS.get(fuente, fuente)
    if nombre not in FUENTES:
        return None
    for ext in ('.jsonl','.csv'):
        p = root / '04_logs' / f'{nombre}{ext}'
        if p.is_file():
            return p
    return None


def log_contiene_evento(ruta: Path, event_id: str):
    """Escaneo puntual SOLO al confirmar manualmente, nunca en cada ticket."""
    with ruta.open('r',encoding='utf-8-sig', errors='replace', newline='') as f:
        if ruta.suffix == '.csv':
            return any(row.get('event_id') == event_id for row in csv.DictReader(f))
        for linea in f:
            if event_id not in linea:
                continue
            try:
                if json.loads(linea).get('event_id') == event_id:
                    return True
            except ValueError:
                continue
    return False


def confirmar_grupo(root: Path, group_id: str, analista: str,
                    justificacion: str, evidencias: list[str]):
    if not re.fullmatch(r'INC-[A-Za-z0-9-]+', group_id):
        raise ValueError('ID de grupo inválido')
    if not analista.strip() or len(justificacion.strip()) < 50:
        raise ValueError('Debes indicar analista y justificación causal (>= 50 caracteres)')
    _, por_id = indice_grupos(root)
    if group_id not in por_id:
        raise ValueError('Grupo no encontrado en incidentes_candidatos.json')
    grupo = por_id[group_id]
    alert_ids = grupo['alert_ids']
    if len(set(alert_ids)) < 2:
        raise ValueError('No se confirma una cadena de una sola alerta')
    firmas = firma_tickets(root, alert_ids)
    if firmas is None:
        raise ValueError('Hay alertas del grupo sin ticket; investígalas antes de confirmar')
    verificadas: dict[str,list[str]] = {}
    archivos_logs: dict[str,dict] = {}
    for spec in evidencias:
        if '=' not in spec:
            raise ValueError('Formato: --evento ALR-ID=EVENT-ID')
        aid,eid = spec.split('=',1)
        if aid not in alert_ids or not eid.strip():
            raise ValueError('Alerta o evento no pertenece al grupo')
        t = leer_json(ticket_ubicacion(root,aid))
        hits = [e for e in t.get('evidence',[])
                if isinstance(e,dict) and e.get('event_id') == eid]
        if not hits:
            raise ValueError(f'El ticket {aid} no cita el evento {eid}')
        source = hits[0].get('source','')
        ruta = ruta_log(root, source)
        if ruta is None or not log_contiene_evento(ruta,eid):
            raise ValueError(f'El evento {eid} no está comprobado en 04_logs/{source}')
        verificadas.setdefault(aid,[]).append(eid)
        stat = ruta.stat()
        archivos_logs[str(ruta.relative_to(root))] = {'size':stat.st_size, 'mtime_ns':stat.st_mtime_ns}
    if len(verificadas)<2 or len({ev for ids in verificadas.values() for ev in ids})<2:
        raise ValueError('Se necesitan al menos dos tickets y dos eventos diferentes de los logs')
    revision = {'group_id':group_id,'decision':'cadena_confirmada_por_analista',
                'analista':analista.strip(),'justificacion':justificacion.strip(),
                'eventos_contrastados':verificadas,'firma_grupo':firma_grupo(grupo),
                'firmas_tickets':firmas,'firmas_logs':archivos_logs,
                'fecha_utc':datetime.now(timezone.utc).isoformat(),
                'advertencia':'La causalidad la confirma el analista, no el algoritmo.'}
    ruta = root / REVISIONES / f'{group_id}.json'
    guardar_json(ruta,revision)
    return ruta


def revision_vigente(root: Path, grupo: dict):
    path = root / REVISIONES / f"{grupo['id']}.json"
    if not path.is_file():
        return False
    try:
        rev = leer_json(path)
        if rev.get('decision') != 'cadena_confirmada_por_analista':
            return False
        if rev.get('firma_grupo') != firma_grupo(grupo):
            return False
        if rev.get('firmas_tickets') != firma_tickets(root,grupo['alert_ids']):
            return False
        for rel, old in rev.get('firmas_logs',{}).items():
            log = root / rel
            if not log.is_file():
                return False
            st=log.stat()
            if st.st_mtime_ns != old.get('mtime_ns') or st.st_size != old.get('size'):
                return False
        return True
    except (ValueError,OSError,KeyError):
        return False


def subir_nivel(nivel: str):
    if nivel not in NIVELES:
        raise ValueError('Severidad N1 no válida; no se calculará riesgo N2')
    return NIVELES[min(len(NIVELES)-1,NIVELES.index(nivel)+1)]


def evaluar_riesgo_n2(root: Path, ticket: dict, alert_id: str):
    """Evalúa +1 contextual SOLO en auditoría; NUNCA modifica el ticket N1."""
    nivel = ticket.get('severity')
    if nivel not in NIVELES:
        raise ValueError('Severidad N1 fuera del esquema')
    confirmados = [g['id'] for g in grupos_alerta(root,alert_id)
                   if revision_vigente(root,g)]
    delta = 1 if confirmados and ticket.get('verdict') == 'true_positive' else 0
    return {'alert_id':alert_id, 'ticket_id':ticket.get('ticket_id'),
            'severity_n1_oficial':nivel, 'delta_correlacion_n2':delta,
            'severity_n2_contextual':subir_nivel(nivel) if delta else nivel,
            'grupos_confirmados':confirmados,
            'estado':'confirmada_por_analista' if confirmados else 'hipotesis_o_sin_grupo',
            'politica':'El +1 de N2 es ADAPTACIÓN DEL EQUIPO, no parte de la matriz oficial. '
                      'Sin confirmación humana el ajuste es 0; NO existe -1 por correlación.',
            'generado_utc':datetime.now(timezone.utc).isoformat()}


def main():
    p=argparse.ArgumentParser(description='Correlación contextual v3 (sin llamadas a IA)')
    cmd=p.add_mutually_exclusive_group(required=True)
    cmd.add_argument('--alerta',help='Mostrar candidatos de una alerta')
    cmd.add_argument('--confirmar',help='Registrar confirmación humana de un grupo')
    cmd.add_argument('--reevaluar',action='store_true',help='Actualizar evaluaciones N2 sin IA')
    p.add_argument('--analista',default='')
    p.add_argument('--justificacion',default='')
    p.add_argument('--evento',action='append',default=[],help='ALR-ID=EVENT-ID; repetir')
    args=p.parse_args()
    root=Path(__file__).resolve().parent
    if args.alerta:
        salida={'contexto':contexto_alerta(root,args.alerta)}
        ruta=ticket_ubicacion(root,args.alerta)
        if ruta:
            salida['evaluacion_n2']=evaluar_riesgo_n2(root,leer_json(ruta),args.alerta)
        print(json.dumps(salida,ensure_ascii=False,indent=2))
    elif args.confirmar:
        ruta=confirmar_grupo(root,args.confirmar,args.analista,args.justificacion,args.evento)
        print('Confirmación registrada:',ruta)
    else:
        count=0
        for ruta in sorted((root / TICKETS_V3).glob('ALR-*.json')):
            t=leer_json(ruta)
            if ruta.stem not in t.get('alert_ids',[]):
                continue
            guardar_json(root / 'resultados/v3/auditorias'/ruta.name,
                         evaluar_riesgo_n2(root,t,ruta.stem))
            count+=1
        print(f'Evaluaciones N2 actualizadas: {count}; tickets N1 intactos.')


if __name__ == '__main__':
    main()
